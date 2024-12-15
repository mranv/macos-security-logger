use clap::Parser;
use tracing::{info, error, debug};
use tokio::fs;
use std::path::Path;
use std::process;
use tracing_subscriber::{self, fmt, EnvFilter};

use macos_security_logger::{Config, LogCollector};

#[derive(Parser, Debug)]
#[command(
    author = "Anubhav Gain",
    version,
    about = "A robust security log collector for macOS systems",
    long_about = "Collect, process, and analyze macOS security logs with advanced filtering and categorization capabilities."
)]
struct Args {
    /// Output file name
    #[arg(short, long, default_value = "security_logs.json")]
    output: String,

    /// Config file path
    #[arg(short, long)]
    config: Option<String>,

    /// Enable verbose logging
    #[arg(long)]
    verbose: bool,

    /// Time range in hours (e.g., 24 for last 24 hours)
    #[arg(long)]
    hours: Option<u32>,

    /// Specific categories to collect (comma-separated)
    #[arg(long, value_delimiter = ',')]
    categories: Option<Vec<String>>,

    /// Start time in format YYYY-MM-DD HH:MM:SS
    #[arg(long)]
    start_time: Option<String>,

    /// End time in format YYYY-MM-DD HH:MM:SS
    #[arg(long)]
    end_time: Option<String>,

    /// Output format (json or pretty, default: pretty)
    #[arg(long, default_value = "pretty")]
    format: String,

    /// Save raw log output
    #[arg(long)]
    save_raw: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Initialize logging
    setup_logging(args.verbose)?;

    info!("Starting macOS security log collector...");
    debug!("Parsed arguments: {:?}", args);

    // Load and update configuration
    let mut config = match Config::load(args.config.as_deref()) {
        Ok(config) => config,
        Err(e) => {
            error!("Failed to load configuration: {}", e);
            process::exit(1);
        }
    };

    // Update config based on CLI arguments
    if let Err(e) = update_config_from_args(&mut config, &args) {
        error!("Failed to update configuration: {}", e);
        process::exit(1);
    }

    // Ensure output directory exists
    if !Path::new(&config.output_dir).exists() {
        info!("Creating output directory: {:?}", config.output_dir);
        if let Err(e) = fs::create_dir_all(&config.output_dir).await {
            error!("Failed to create output directory: {}", e);
            process::exit(1);
        }
    }

    // Create log collector
    let collector = LogCollector::new(config);

    // Run with CTRL+C handling
    match collector.run_with_ctrl_c().await {
        Ok(()) => {
            info!("Log collection completed successfully");
            process::exit(0);
        }
        Err(e) => {
            error!("Failed to collect logs: {}", e);
            process::exit(1);
        }
    }
}

fn setup_logging(verbose: bool) -> anyhow::Result<()> {
    let filter = if verbose {
        EnvFilter::from("debug")
    } else {
        EnvFilter::from("info")
    };

    fmt()
        .with_env_filter(filter)
        .with_file(true)
        .with_line_number(true)
        .with_thread_ids(true)
        .with_target(false)
        .with_ansi(true)
        .pretty()
        .try_init()
        .map_err(|e| anyhow::anyhow!("Failed to set up logging: {}", e))?;

    Ok(())
}

fn update_config_from_args(config: &mut Config, args: &Args) -> anyhow::Result<()> {
    // Handle time range options
    if let Some(hours) = args.hours {
        config.time_range = Some(format!("{}h", hours));
    }

    // Handle custom time range
    if args.start_time.is_some() || args.end_time.is_some() {
        config.start_time = args.start_time.clone();
        config.end_time = args.end_time.clone();
    }

    // Handle categories
    if let Some(categories) = &args.categories {
        debug!("Filtering for categories: {:?}", categories);
        config.filter_categories(categories);
    }

    // Handle output format
    config.json_pretty_print = match args.format.to_lowercase().as_str() {
        "pretty" => true,
        "json" => false,
        _ => {
            error!("Invalid output format '{}', using pretty print", args.format);
            true
        }
    };

    // Handle raw output saving
    config.save_raw_json = args.save_raw;

    // Validate the updated configuration
    config.validate().map_err(|e| anyhow::anyhow!("Configuration error: {}", e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arg_parsing() {
        let args = Args::try_parse_from([
            "program",
            "--verbose",
            "--hours", "24",
            "--categories", "network_security,authentication",
        ]).unwrap();

        assert!(args.verbose);
        assert_eq!(args.hours, Some(24));
        assert_eq!(
            args.categories,
            Some(vec!["network_security".to_string(), "authentication".to_string()])
        );
    }

    #[test]
    fn test_config_update() {
        let args = Args::try_parse_from([
            "program",
            "--hours", "24",
            "--format", "json",
        ]).unwrap();

        let mut config = Config::load(None).unwrap();
        update_config_from_args(&mut config, &args).unwrap();

        assert_eq!(config.time_range, Some("24h".to_string()));
        assert!(!config.json_pretty_print);
    }

    #[test]
    fn test_invalid_format() {
        let args = Args::try_parse_from([
            "program",
            "--format", "invalid",
        ]).unwrap();

        let mut config = Config::load(None).unwrap();
        update_config_from_args(&mut config, &args).unwrap();

        // Should default to pretty print for invalid format
        assert!(config.json_pretty_print);
    }
}