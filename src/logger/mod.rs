use crate::config::Config;
use crate::error::LoggerError;
use crate::utils;
use chrono::Local;
use std::process::Command;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tracing::{debug, error, info};

pub mod models;
use models::{LogEntry, LogOutput};

pub struct LogCollector {
    config: Config,
}

impl LogCollector {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    pub async fn collect_logs(&self) -> Result<(), LoggerError> {
        info!("Starting log collection");
        let logs = self.read_security_logs().await?;
        
        if logs.is_empty() {
            info!("No logs found matching criteria");
            return Ok(());
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
                .map_err(LoggerError::CommandError)?;

            if !output.status.success() {
                error!(
                    "Log command failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                continue;
            }

            let raw_output = String::from_utf8_lossy(&output.stdout);
            
            // Save raw command output for debugging
            File::create(&raw_output_path)
                .await
                .map_err(|e| LoggerError::FileAccessError(e.to_string()))?
                .write_all(raw_output.as_bytes())
                .await
                .map_err(|e| LoggerError::FileAccessError(e.to_string()))?;

            debug!("Saved raw command output to {:?}", raw_output_path);

            // Parse the output
            match serde_json::from_str::<Vec<LogEntry>>(&raw_output) {
                Ok(entries) => {
                    info!("Successfully parsed {} log entries", entries.len());
                    logs.extend(entries);
                }
                Err(e) => {
                    error!("Failed to parse log entries: {}", e);
                    // Save the problematic output to a debug file
                    let debug_file = self.config.output_dir.join(
                        format!("debug_log_{}.json", timestamp)
                    );
                    tokio::fs::write(&debug_file, raw_output.as_bytes())
                        .await
                        .map_err(|e| LoggerError::FileAccessError(e.to_string()))?;
                    error!("Saved problematic output to {:?}", debug_file);
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
        }.map_err(|e| LoggerError::ParseError(e.into()))?;

        File::create(&output_path)
            .await
            .map_err(|e| LoggerError::FileAccessError(e.to_string()))?
            .write_all(json.as_bytes())
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
        }.map_err(|e| LoggerError::ParseError(e.into()))?;

        File::create(&raw_path)
            .await
            .map_err(|e| LoggerError::FileAccessError(e.to_string()))?
            .write_all(json.as_bytes())
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