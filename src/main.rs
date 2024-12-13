use clap::Parser;
use tracing::{info, error};

mod config;
mod error;
mod logger;
mod utils;

use crate::config::Config;
use crate::logger::LogCollector;

#[derive(Parser)]
#[command(author, version, about)]
struct Args {
    #[arg(short, long, default_value = "security_logs.json")]
    output: String,

    #[arg(short, long)]
    config: Option<String>,

    #[arg(long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Initialize tracing
    tracing_subscriber::FmtSubscriber::builder()
        .with_env_filter(if args.verbose { "debug" } else { "info" })
        .with_file(true)
        .with_line_number(true)
        .with_thread_ids(true)
        .pretty()
        .init();

    info!("Starting macOS security log collector...");

    let config = Config::load(args.config.as_deref())?;
    let collector = LogCollector::new(config);

    match collector.collect_logs().await {
        Ok(()) => info!("Log collection completed successfully"),
        Err(e) => {
            error!("Failed to collect logs: {}", e);
            std::process::exit(1);
        }
    }

    Ok(())
}