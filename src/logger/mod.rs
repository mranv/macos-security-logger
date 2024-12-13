use crate::config::Config;
use crate::error::LoggerError;
use crate::utils;
use chrono::Local;
use std::process::Command;
use tracing::{debug, error, info};
use tokio::fs;

pub mod models;
use models::{LogEntry, LogOutput};

pub struct LogCollector {
    config: Config,
}

impl LogCollector {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    fn validate_config(&self) -> Result<(), LoggerError> {
        if self.config.retention_days == 0 {
            return Err(LoggerError::ConfigError("retention_days must be greater than 0".to_string()));
        }
        if self.config.max_file_size == 0 {
            return Err(LoggerError::ConfigError("max_file_size must be greater than 0".to_string()));
        }
        if self.config.log_patterns.is_empty() {
            return Err(LoggerError::ConfigError("log_patterns cannot be empty".to_string()));
        }
        Ok(())
    }

    pub async fn collect_logs(&self) -> Result<(), LoggerError> {
        // Validate configuration first
        self.validate_config()?;

        info!("Starting log collection");
        let logs = self.read_security_logs().await?;
        
        if logs.is_empty() {
            info!("No logs found matching criteria");
            return Ok(());
        }

        // Ensure output directory exists
        if !self.config.output_dir.exists() {
            fs::create_dir_all(&self.config.output_dir)
                .await
                .map_err(|e| LoggerError::FileAccessError(format!("Failed to create output directory: {}", e)))?;
        }

        // Save formatted logs
        info!("Saving {} log entries", logs.len());
        self.save_logs(&logs).await?;

        // Save raw logs if configured
        if self.config.save_raw_json {
            self.save_raw_json(&logs).await?;
        }

        self.rotate_logs().await?;
        Ok(())
    }

    async fn read_security_logs(&self) -> Result<Vec<LogEntry>, LoggerError> {
        debug!("Reading security logs");
        let mut logs = Vec::new();
        debug!("Using output directory: {:?}", self.config.output_dir);

        let timestamp = Local::now().format("%Y%m%d_%H%M%S").to_string();
        let raw_output_path = self.config.output_dir.join(format!("raw_output_{}.json", timestamp));

        for pattern in &self.config.log_patterns {
            debug!("Processing log pattern: {}", pattern);
            let output = Command::new("log")
                .arg("show")
                .arg("--predicate")
                .arg(pattern)
                .arg("--style")
                .arg("json")
                .arg("--last")
                .arg("24h")
                .output()
                .map_err(|e| LoggerError::CommandError(e))?;

            if !output.status.success() {
                let error_msg = String::from_utf8_lossy(&output.stderr);
                error!("Log command failed: {}", error_msg);
                return Err(LoggerError::CommandError(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    error_msg.to_string(),
                )));
            }

            let raw_output = String::from_utf8_lossy(&output.stdout);
            debug!("Raw log output sample: {:.200}...", raw_output);

            // Save raw command output for debugging
            if let Err(e) = fs::write(&raw_output_path, raw_output.as_bytes()).await {
                error!("Failed to save raw output: {}", e);
            }

            match serde_json::from_str::<Vec<LogEntry>>(&raw_output) {
                Ok(entries) => {
                    info!("Successfully parsed {} log entries", entries.len());
                    logs.extend(entries);
                }
                Err(e) => {
                    error!("Failed to parse log entries: {}", e);
                    // Save problematic output
                    let debug_file = self.config.output_dir.join(
                        format!("debug_log_{}.json", timestamp)
                    );
                    if let Err(write_err) = fs::write(&debug_file, raw_output.as_bytes()).await {
                        error!("Failed to save debug file: {}", write_err);
                    }
                }
            }
        }

        Ok(logs)
    }

    async fn save_logs(&self, logs: &[LogEntry]) -> Result<(), LoggerError> {
        let timestamp = Local::now().format("%Y%m%d_%H%M%S");
        let output_path = self.config.output_dir.join(
            format!("security_logs_{}.json", timestamp)
        );

        let output = LogOutput::new(logs);
        let json = if self.config.json_pretty_print {
            serde_json::to_string_pretty(&output)
        } else {
            serde_json::to_string(&output)
        }.map_err(|e| LoggerError::ParseError(e))?;

        fs::write(&output_path, json)
            .await
            .map_err(|e| LoggerError::FileAccessError(e.to_string()))?;

        info!("Saved formatted logs to {:?}", output_path);
        Ok(())
    }

    async fn save_raw_json(&self, logs: &[LogEntry]) -> Result<(), LoggerError> {
        let timestamp = Local::now().format("%Y%m%d_%H%M%S");
        let raw_path = self.config.output_dir.join(
            format!("security_logs_raw_{}.json", timestamp)
        );

        let json = if self.config.json_pretty_print {
            serde_json::to_string_pretty(logs)
        } else {
            serde_json::to_string(logs)
        }.map_err(|e| LoggerError::ParseError(e))?;

        fs::write(&raw_path, json)
            .await
            .map_err(|e| LoggerError::FileAccessError(e.to_string()))?;

        info!("Saved raw logs to {:?}", raw_path);
        Ok(())
    }

    async fn rotate_logs(&self) -> Result<(), LoggerError> {
        utils::cleanup_old_logs(
            &self.config.output_dir,
            self.config.retention_days,
            self.config.max_file_size,
        )
        .await
        .map_err(|e| LoggerError::FileAccessError(e.to_string()))
    }
}