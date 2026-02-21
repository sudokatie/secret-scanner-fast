use crate::utils::binary::is_binary_content;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Result};
use std::path::Path;

const DEFAULT_BUF_SIZE: usize = 8192;
const MAX_LINE_LENGTH: usize = 65536;

pub struct StreamReader {
    max_line_length: usize,
}

impl StreamReader {
    pub fn new() -> Self {
        Self {
            max_line_length: MAX_LINE_LENGTH,
        }
    }

    /// Check if file should be skipped (binary or too large)
    pub fn should_skip(&self, path: &Path, max_size: u64) -> Result<bool> {
        let metadata = std::fs::metadata(path)?;

        if metadata.len() > max_size {
            return Ok(true);
        }

        // Check first 512 bytes for binary content
        let mut file = File::open(path)?;
        let mut buffer = [0u8; 512];
        let bytes_read = file.read(&mut buffer)?;

        Ok(is_binary_content(&buffer[..bytes_read]))
    }

    /// Read file as iterator of (line_number, line_content)
    pub fn read_file(&self, path: &Path) -> Result<impl Iterator<Item = (usize, String)>> {
        let file = File::open(path)?;
        let reader = BufReader::with_capacity(DEFAULT_BUF_SIZE, file);
        Ok(LineIterator::new(reader, self.max_line_length))
    }
}

impl Default for StreamReader {
    fn default() -> Self {
        Self::new()
    }
}

struct LineIterator<R: BufRead> {
    reader: R,
    line_num: usize,
    max_length: usize,
    buffer: String,
}

impl<R: BufRead> LineIterator<R> {
    fn new(reader: R, max_length: usize) -> Self {
        Self {
            reader,
            line_num: 0,
            max_length,
            buffer: String::with_capacity(256),
        }
    }
}

impl<R: BufRead> Iterator for LineIterator<R> {
    type Item = (usize, String);

    fn next(&mut self) -> Option<Self::Item> {
        self.buffer.clear();

        match self.reader.read_line(&mut self.buffer) {
            Ok(0) => None,
            Ok(_) => {
                self.line_num += 1;

                // Truncate overly long lines
                if self.buffer.len() > self.max_length {
                    self.buffer.truncate(self.max_length);
                }

                // Remove trailing newline
                if self.buffer.ends_with('\n') {
                    self.buffer.pop();
                    if self.buffer.ends_with('\r') {
                        self.buffer.pop();
                    }
                }

                Some((self.line_num, std::mem::take(&mut self.buffer)))
            }
            Err(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_read_file() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "line1").unwrap();
        writeln!(file, "line2").unwrap();
        writeln!(file, "line3").unwrap();

        let reader = StreamReader::new();
        let lines: Vec<_> = reader.read_file(file.path()).unwrap().collect();

        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], (1, "line1".to_string()));
        assert_eq!(lines[1], (2, "line2".to_string()));
        assert_eq!(lines[2], (3, "line3".to_string()));
    }

    #[test]
    fn test_crlf_handling() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"line1\r\nline2\r\n").unwrap();

        let reader = StreamReader::new();
        let lines: Vec<_> = reader.read_file(file.path()).unwrap().collect();

        assert_eq!(lines[0].1, "line1");
        assert_eq!(lines[1].1, "line2");
    }

    #[test]
    fn test_skip_large_file() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(&vec![b'x'; 1000]).unwrap();

        let reader = StreamReader::new();
        assert!(reader.should_skip(file.path(), 500).unwrap());
        assert!(!reader.should_skip(file.path(), 2000).unwrap());
    }
}
