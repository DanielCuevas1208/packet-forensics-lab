use clap::{Parser, Subcommand, ValueEnum};
use packet_forensics_lab::{fixtures, loader, render, tui};

/// Packet Forensics Lab.
///
/// Inspect bundled packet captures and read the explained anomalies.
/// The lab is offline and performs no active scanning.
#[derive(Parser, Debug)]
#[command(name = "pfl", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Open the interactive terminal interface.
    Tui,
    /// Analyze one bundled fixture or an external pcap file and print a report.
    Scan {
        /// A bundled fixture name or a path to a pcap file.
        target: String,
        /// Output format. Defaults to plain text suitable for a terminal.
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// List the bundled fixtures.
    List,
}

/// Report shape written by the scan command.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    /// Deterministic, human-readable text.
    Text,
    /// Deterministic JSON report (schema packet-forensics-lab/report/v1).
    Json,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        None | Some(Command::Tui) => {
            tui::run().await?;
        }
        Some(Command::Scan { target, format }) => {
            let loaded = if let Some(fixture) = fixtures::find(&target) {
                loader::load_path(fixture.title, &fixtures::path(fixture.filename)).await?
            } else {
                let path = std::path::PathBuf::from(&target);
                let title = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or(&target)
                    .to_string();
                loader::load_path(&title, &path).await?
            };
            let output = match format {
                OutputFormat::Text => render::text(&loaded.report),
                OutputFormat::Json => render::json(&loaded.report),
            };
            println!("{output}");
        }
        Some(Command::List) => {
            println!("{:<12} SCENARIO", "NAME");
            for fixture in fixtures::all() {
                println!("{:<12} {}", fixture.name, fixture.title);
            }
        }
    }
    Ok(())
}
