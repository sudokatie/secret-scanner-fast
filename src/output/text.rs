use crate::detection::rules::Severity;
use crate::output::finding::Finding;
use crate::output::ScanResult;
use std::io::{self, Write};
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};

pub struct TextFormatter {
    use_color: bool,
    show_redacted: bool,
}

impl TextFormatter {
    pub fn new(use_color: bool) -> Self {
        Self {
            use_color,
            show_redacted: true,
        }
    }

    pub fn with_no_redact(mut self) -> Self {
        self.show_redacted = false;
        self
    }

    fn severity_color(&self, severity: Severity) -> Color {
        match severity {
            Severity::High => Color::Red,
            Severity::Medium => Color::Yellow,
            Severity::Low => Color::Blue,
        }
    }

    pub fn format_finding<W: Write>(&self, w: &mut W, finding: &Finding) -> io::Result<()> {
        let value = if self.show_redacted {
            finding.redacted_match()
        } else {
            finding.matched_value.clone()
        };

        writeln!(
            w,
            "{}:{}:{}: {} [{}] {}",
            finding.location.file.display(),
            finding.location.line,
            finding.location.column,
            finding.rule_id,
            finding.severity,
            value
        )
    }

    pub fn format_finding_colored(&self, finding: &Finding) -> io::Result<()> {
        let mut stdout = StandardStream::stdout(if self.use_color {
            ColorChoice::Auto
        } else {
            ColorChoice::Never
        });

        // File:line:col in default color
        write!(
            stdout,
            "{}:{}:{}: ",
            finding.location.file.display(),
            finding.location.line,
            finding.location.column
        )?;

        // Rule ID
        stdout.set_color(ColorSpec::new().set_bold(true))?;
        write!(stdout, "{}", finding.rule_id)?;
        stdout.reset()?;

        // Severity in color
        write!(stdout, " [")?;
        stdout.set_color(
            ColorSpec::new()
                .set_fg(Some(self.severity_color(finding.severity)))
                .set_bold(true),
        )?;
        write!(stdout, "{}", finding.severity)?;
        stdout.reset()?;
        write!(stdout, "] ")?;

        // Value
        let value = if self.show_redacted {
            finding.redacted_match()
        } else {
            finding.matched_value.clone()
        };
        writeln!(stdout, "{}", value)?;

        Ok(())
    }

    pub fn format_result(&self, result: &ScanResult) -> io::Result<()> {
        for finding in &result.findings {
            if self.use_color {
                self.format_finding_colored(finding)?;
            } else {
                self.format_finding(&mut io::stdout(), finding)?;
            }
        }

        // Summary
        let mut stdout = StandardStream::stdout(if self.use_color {
            ColorChoice::Auto
        } else {
            ColorChoice::Never
        });

        writeln!(stdout)?;

        if result.findings.is_empty() {
            stdout.set_color(ColorSpec::new().set_fg(Some(Color::Green)).set_bold(true))?;
            writeln!(stdout, "No secrets found")?;
        } else {
            stdout.set_color(ColorSpec::new().set_fg(Some(Color::Red)).set_bold(true))?;
            writeln!(stdout, "Found {} secrets", result.findings.len())?;
        }
        stdout.reset()?;

        let high = result.count_by_severity(Severity::High);
        let medium = result.count_by_severity(Severity::Medium);
        let low = result.count_by_severity(Severity::Low);

        if !result.findings.is_empty() {
            writeln!(stdout, "  High:   {}", high)?;
            writeln!(stdout, "  Medium: {}", medium)?;
            writeln!(stdout, "  Low:    {}", low)?;
        }

        writeln!(stdout)?;
        writeln!(
            stdout,
            "Scanned {} files ({} bytes) in {:.2}s",
            result.files_scanned,
            result.bytes_scanned,
            result.scan_duration.as_secs_f64()
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::finding::Location;
    use std::path::PathBuf;

    fn test_finding() -> Finding {
        Finding {
            rule_id: "aws-access-key".to_string(),
            severity: Severity::High,
            location: Location {
                file: PathBuf::from("config.py"),
                line: 10,
                column: 5,
                end_column: 25,
            },
            matched_value: "AKIAIOSFODNN7EXAMPLE".to_string(),
            context: "key = AKIAIOSFODNN7EXAMPLE".to_string(),
            git_info: None,
        }
    }

    #[test]
    fn test_format_finding() {
        let formatter = TextFormatter::new(false);
        let finding = test_finding();
        let mut buf = Vec::new();

        formatter.format_finding(&mut buf, &finding).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("config.py:10:5"));
        assert!(output.contains("aws-access-key"));
        assert!(output.contains("[high]"));
        // Should be redacted
        assert!(output.contains("AKIA"));
        assert!(output.contains("..."));
    }

    #[test]
    fn test_format_no_redact() {
        let formatter = TextFormatter::new(false).with_no_redact();
        let finding = test_finding();
        let mut buf = Vec::new();

        formatter.format_finding(&mut buf, &finding).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!output.contains("..."));
    }
}
