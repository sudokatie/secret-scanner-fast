/// Check if content appears to be binary
pub fn is_binary_content(content: &[u8]) -> bool {
    if content.is_empty() {
        return false;
    }

    // Check for null bytes (strong binary indicator)
    if content.contains(&0) {
        return true;
    }

    // Count non-printable characters (excluding tab, LF, CR)
    let non_printable = content
        .iter()
        .filter(|&&b| b < 32 && b != 9 && b != 10 && b != 13)
        .count();

    // More than 10% non-printable suggests binary
    non_printable > content.len() / 10
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty() {
        assert!(!is_binary_content(&[]));
    }

    #[test]
    fn test_text() {
        assert!(!is_binary_content(b"Hello, world!\n"));
        assert!(!is_binary_content(b"line1\nline2\tindented"));
    }

    #[test]
    fn test_binary_null() {
        assert!(is_binary_content(b"Hello\x00World"));
    }

    #[test]
    fn test_binary_ratio() {
        // More than 10% non-printable
        assert!(is_binary_content(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 65]));
    }
}
