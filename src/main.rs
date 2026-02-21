use clap::Parser;
use std::path::PathBuf;
use std::process::ExitCode;

mod cli;
mod config;
mod detection;
mod output;
mod scanner;
mod utils;

use cli::args::{Args, Command, InitArgs, ScanArgs};
use config::Config;
use scanner::engine::ScanEngine;

fn main() -> ExitCode {
    let args = Args::parse();

    match args.command {
        Some(Command::Scan(scan_args)) => run_scan(scan_args),
        Some(Command::Rules(rules_args)) => {
            run_rules(&rules_args);
            ExitCode::SUCCESS
        }
        Some(Command::Init(init_args)) => run_init(&init_args),
        None => {
            // Default: scan current directory
            let scan_args = ScanArgs {
                path: PathBuf::from("."),
                format: cli::args::OutputFormat::Text,
                output: None,
                min_severity: cli::args::SeverityArg::Low,
                no_color: false,
                no_redact: false,
                git_history: false,
                since: None,
                commits: None,
                staged: false,
                diff: None,
                max_file_size: 1048576,
                exclude: vec![],
                include: vec![],
                config: None,
                no_config: false,
                baseline: None,
                threads: None,
                verbose: 0,
                quiet: false,
            };
            run_scan(scan_args)
        }
    }
}

fn run_scan(args: ScanArgs) -> ExitCode {
    let path = args.path.clone();
    let engine = ScanEngine::from_args(&args);

    match engine.run(&path) {
        Ok(has_findings) => {
            if has_findings {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            ExitCode::from(2)
        }
    }
}

fn run_rules(args: &cli::args::RulesArgs) {
    use detection::patterns::all_patterns;

    let patterns = all_patterns();

    // Filter by severity if specified
    let filtered: Vec<_> = if let Some(ref sev) = args.severity {
        let min_sev = match sev {
            cli::args::SeverityArg::Low => detection::rules::Severity::Low,
            cli::args::SeverityArg::Medium => detection::rules::Severity::Medium,
            cli::args::SeverityArg::High => detection::rules::Severity::High,
        };
        patterns.into_iter().filter(|p| p.severity >= min_sev).collect()
    } else {
        patterns
    };

    match args.format {
        cli::args::OutputFormat::Json => {
            println!("[");
            for (i, p) in filtered.iter().enumerate() {
                let comma = if i < filtered.len() - 1 { "," } else { "" };
                println!(
                    r#"  {{"id": "{}", "description": "{}", "severity": "{:?}", "confidence": "{:?}"}}{}"#,
                    p.id, p.description, p.severity, p.confidence, comma
                );
            }
            println!("]");
        }
        _ => {
            println!("{:<25} {:<35} {:>8} {:>10}", "RULE ID", "DESCRIPTION", "SEVERITY", "CONFIDENCE");
            println!("{}", "-".repeat(80));
            for p in filtered {
                println!(
                    "{:<25} {:<35} {:>8} {:>10}",
                    p.id,
                    if p.description.len() > 35 {
                        format!("{}...", &p.description[..32])
                    } else {
                        p.description.to_string()
                    },
                    format!("{:?}", p.severity),
                    format!("{:?}", p.confidence)
                );
            }
        }
    }
}

fn run_init(args: &InitArgs) -> ExitCode {
    use std::fs;

    // Check if file exists
    if args.output.exists() && !args.force {
        eprintln!(
            "Error: {} already exists. Use --force to overwrite.",
            args.output.display()
        );
        return ExitCode::from(1);
    }

    // Generate config
    let config = if args.full {
        Config::full()
    } else {
        Config::minimal()
    };

    // Write config
    match config.to_yaml() {
        Ok(yaml) => {
            if let Err(e) = fs::write(&args.output, &yaml) {
                eprintln!("Error writing config: {}", e);
                return ExitCode::from(2);
            }
            println!("Created {}", args.output.display());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Error generating config: {}", e);
            ExitCode::from(2)
        }
    }
}
