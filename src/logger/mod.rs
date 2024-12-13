use crate::config::Config;
use crate::error::LoggerError;
use crate::utils;
use chrono::{DateTime, Local};
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

        self.save_logs(&logs).await?;
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
                .output()
                .map_err(LoggerError::CommandError)?;

            if !output.status.success() {
                error!(
                    "Log command failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                continue;
            }

            let entries: Vec<LogEntry> = serde_json::from_slice(&output.stdout)
                .map_err(LoggerError::ParseError)?;

            logs.extend(entries);
        }

        Ok(logs)
    }

    async fn save_logs(&self, logs: &[LogEntry]) -> Result<(), LoggerError> {
        let output_path = self.config.output_dir.join(format!(
            "security_logs_{}.json",
            Local::now().format("%Y%m%d_%H%M%S")
        ));

        let mut file = File::create(&output_path)
            .await
            .map_err(|e| LoggerError::FileAccessError(e.to_string()))?;

        let output = LogOutput::new(logs);
        let json = serde_json::to_string_pretty(&output)
            .map_err(LoggerError::ParseError)?;

        file.write_all(json.as_bytes())
            .await
            .map_err(|e| LoggerError::FileAccessError(e.to_string()))?;

        info!("Saved {} log entries to {:?}", logs.len(), output_path);
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