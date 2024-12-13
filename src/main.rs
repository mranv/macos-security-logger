use clap::Parser;
use tracing::{info, error};
use tokio::fs;
use std::path::Path;

use macos_security_logger::{Config, LogCollector};

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
    
    // Ensure output directory exists
    if !Path::new(&config.output_dir).exists() {
        info!("Creating output directory: {:?}", config.output_dir);
        fs::create_dir_all(&config.output_dir).await?;
    }

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