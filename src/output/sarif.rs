use crate::detection::patterns::all_patterns;
use crate::detection::rules::Severity;
use crate::output::finding::Finding;
use crate::output::ScanResult;
use serde::Serialize;
use std::io::{self, Write};

const SARIF_VERSION: &str = "2.1.0";
const SARIF_SCHEMA: &str = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifReport {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifDriver {
    name: &'static str,
    version: &'static str,
    information_uri: &'static str,
    rules: Vec<SarifRule>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRule {
    id: String,
    short_description: SarifMessage,
    default_configuration: SarifConfiguration,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifConfiguration {
    level: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifResult {
    rule_id: String,
    level: String,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
    fingerprints: SarifFingerprints,
}

#[derive(Serialize)]
struct SarifMessage {
    text: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifLocation {
    physical_location: SarifPhysicalLocation,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifPhysicalLocation {
    artifact_location: SarifArtifactLocation,
    region: SarifRegion,
}

#[derive(Serialize)]
struct SarifArtifactLocation {
    uri: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRegion {
    start_line: usize,
    start_column: usize,
    end_column: usize,
}

#[derive(Serialize)]
struct SarifFingerprints {
    #[serde(rename = "secret-scanner/v1")]
    v1: String,
}

pub struct SarifFormatter {
    redact: bool,
}

impl SarifFormatter {
    pub fn new() -> Self {
        Self { redact: true }
    }

    pub fn no_redact(mut self) -> Self {
        self.redact = false;
        self
    }

    fn severity_to_level(severity: Severity) -> &'static str {
        match severity {
            Severity::High => "error",
            Severity::Medium => "warning",
            Severity::Low => "note",
        }
    }

    fn build_rules() -> Vec<SarifRule> {
        all_patterns()
            .into_iter()
            .map(|p| SarifRule {
                id: p.id.to_string(),
                short_description: SarifMessage {
                    text: p.description.to_string(),
                },
                default_configuration: SarifConfiguration {
                    level: Self::severity_to_level(p.severity).to_string(),
                },
            })
            .collect()
    }

    fn convert_finding(&self, finding: &Finding) -> SarifResult {
        let value = if self.redact {
            finding.redacted_match()
        } else {
            finding.matched_value.clone()
        };

        SarifResult {
            rule_id: finding.rule_id.clone(),
            level: Self::severity_to_level(finding.severity).to_string(),
            message: SarifMessage {
                text: format!(
                    "Potential secret detected: {} ({})",
                    finding.rule_id, value
                ),
            },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: finding.location.file.to_string_lossy().to_string(),
                    },
                    region: SarifRegion {
                        start_line: finding.location.line,
                        start_column: finding.location.column,
                        end_column: finding.location.end_column,
                    },
                },
            }],
            fingerprints: SarifFingerprints {
                v1: finding.fingerprint(),
            },
        }
    }

    pub fn format<W: Write>(&self, w: &mut W, result: &ScanResult) -> io::Result<()> {
        let report = SarifReport {
            schema: SARIF_SCHEMA,
            version: SARIF_VERSION,
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "secret-scanner-fast",
                        version: env!("CARGO_PKG_VERSION"),
                        information_uri: "https://github.com/sudokatie/secret-scanner-fast",
                        rules: Self::build_rules(),
                    },
                },
                results: result
                    .findings
                    .iter()
                    .map(|f| self.convert_finding(f))
                    .collect(),
            }],
        };

        let json = serde_json::to_string_pretty(&report)?;
        writeln!(w, "{}", json)?;

        Ok(())
    }

    pub fn format_to_string(&self, result: &ScanResult) -> Result<String, serde_json::Error> {
        let report = SarifReport {
            schema: SARIF_SCHEMA,
            version: SARIF_VERSION,
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "secret-scanner-fast",
                        version: env!("CARGO_PKG_VERSION"),
                        information_uri: "https://github.com/sudokatie/secret-scanner-fast",
                        rules: Self::build_rules(),
                    },
                },
                results: result
                    .findings
                    .iter()
                    .map(|f| self.convert_finding(f))
                    .collect(),
            }],
        };

        serde_json::to_string_pretty(&report)
    }
}

impl Default for SarifFormatter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::finding::Location;
    use std::path::PathBuf;
    use std::time::Duration;

    fn test_result() -> ScanResult {
        ScanResult {
            findings: vec![Finding {
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
            }],
            files_scanned: 5,
            bytes_scanned: 1024,
            scan_duration: Duration::from_millis(50),
        }
    }

    #[test]
    fn test_sarif_structure() {
        let formatter = SarifFormatter::new();
        let result = test_result();
        let sarif = formatter.format_to_string(&result).unwrap();

        // Check SARIF required fields
        assert!(sarif.contains("\"$schema\""));
        assert!(sarif.contains("2.1.0"));
        assert!(sarif.contains("\"runs\""));
        assert!(sarif.contains("\"tool\""));
        assert!(sarif.contains("\"driver\""));
        assert!(sarif.contains("\"results\""));
    }

    #[test]
    fn test_sarif_finding() {
        let formatter = SarifFormatter::new();
        let result = test_result();
        let sarif = formatter.format_to_string(&result).unwrap();

        assert!(sarif.contains("aws-access-key"));
        assert!(sarif.contains("config.py"));
        assert!(sarif.contains("\"error\"")); // High severity = error
        assert!(sarif.contains("\"startLine\": 10"));
    }

    #[test]
    fn test_sarif_rules() {
        let formatter = SarifFormatter::new();
        let result = ScanResult::new();
        let sarif = formatter.format_to_string(&result).unwrap();

        // Should have rules even with no findings
        assert!(sarif.contains("\"rules\""));
        assert!(sarif.contains("aws-access-key"));
        assert!(sarif.contains("github-token"));
    }

    #[test]
    fn test_sarif_fingerprint() {
        let formatter = SarifFormatter::new();
        let result = test_result();
        let sarif = formatter.format_to_string(&result).unwrap();

        assert!(sarif.contains("secret-scanner/v1"));
        assert!(sarif.contains("fingerprints"));
    }
}
