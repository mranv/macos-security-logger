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

        // Save formatted JSON
        self.save_logs(&logs).await?;
        
        // Save raw JSON if configured
        if self.config.save_raw_json {
            self.save_raw_json(&logs).await?;
        }
        
        self.rotate_logs().await?;
        
        Ok(())
    }

    async fn read_security_logs(&self) -> Result<Vec<LogEntry>, LoggerError> {
        debug!("Reading security logs");
        let mut logs = Vec::new();

        for pattern in &self.config.log_patterns {
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
            debug!("Raw log output sample: {:.200}...", raw_output);

            // Try parsing as array first
            if let Ok(entries) = serde_json::from_str::<Vec<LogEntry>>(&raw_output) {
                info!("Successfully parsed {} log entries", entries.len());
                logs.extend(entries);
                continue;
            }

            // If array parsing fails, try parsing as single object
            if let Ok(entry) = serde_json::from_str::<LogEntry>(&raw_output) {
                info!("Successfully parsed single log entry");
                logs.push(entry);
                continue;
            }

            // Save raw output for debugging
            let debug_file = self.config.output_dir.join(
                format!("debug_log_{}.json", Local::now().format("%Y%m%d_%H%M%S"))
            );
            
            tokio::fs::write(&debug_file, raw_output.as_bytes()).await
                .map_err(|e| LoggerError::FileAccessError(e.to_string()))?;
            
            error!("Failed to parse log output. Debug file saved to: {:?}", debug_file);
        }

        Ok(logs)
    }

    async fn save_logs(&self, logs: &[LogEntry]) -> Result<(), LoggerError> {
        let timestamp = Local::now().format("%Y%m%d_%H%M%S");
        let output_path = self.config.output_dir.join(
            format!("security_logs_{}.json", timestamp)
        );

        let mut file = File::create(&output_path)
            .await
            .map_err(|e| LoggerError::FileAccessError(e.to_string()))?;

        let output = LogOutput::new(logs);
        let json = if self.config.json_pretty_print {
            serde_json::to_string_pretty(&output)
        } else {
            serde_json::to_string(&output)
        }.map_err(|e| LoggerError::ParseError(e.into()))?;

        file.write_all(json.as_bytes())
            .await
            .map_err(|e| LoggerError::FileAccessError(e.to_string()))?;

        info!("Saved {} log entries to {:?}", logs.len(), output_path);
        Ok(())
    }

    async fn save_raw_json(&self, logs: &[LogEntry]) -> Result<(), LoggerError> {
        let timestamp = Local::now().format("%Y%m%d_%H%M%S");
        let raw_path = self.config.output_dir.join(
            format!("security_logs_raw_{}.json", timestamp)
        );

        let mut file = File::create(&raw_path)
            .await
            .map_err(|e| LoggerError::FileAccessError(e.to_string()))?;

        let json = if self.config.json_pretty_print {
            serde_json::to_string_pretty(&logs)
        } else {
            serde_json::to_string(&logs)
        }.map_err(|e| LoggerError::ParseError(e.into()))?;

        file.write_all(json.as_bytes())
            .await
            .map_err(|e| LoggerError::FileAccessError(e.to_string()))?;

        info!("Saved raw JSON to {:?}", raw_path);
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