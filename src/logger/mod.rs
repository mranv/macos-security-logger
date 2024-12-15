use crate::config::Config;
use crate::error::LoggerError;
use crate::utils;
use chrono::Local;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::fs;
use tokio::signal::ctrl_c;
use tracing::{debug, error, info, warn};

pub mod models;
pub mod report;
use models::{LogEntry, LogOutput};
use report::SecurityReport;

pub struct LogCollector {
    config: Config,
    shutdown: Arc<AtomicBool>,
}

impl LogCollector {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    pub async fn run_with_ctrl_c(&self) -> Result<(), LoggerError> {
        let shutdown = self.shutdown.clone();
        
        // Setup CTRL+C handler
        tokio::spawn(async move {
            if let Ok(()) = ctrl_c().await {
                info!("Received CTRL+C, initiating graceful shutdown...");
                shutdown.store(true, Ordering::SeqCst);
            }
        });

        self.collect_logs().await
    }

    fn analyze_log_format(raw_output: &str) -> Result<(), LoggerError> {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(raw_output) {
            if let Some(array) = value.as_array() {
                if let Some(first) = array.first() {
                    debug!("Available fields in log entry:");
                    if let Some(obj) = first.as_object() {
                        for (key, value_type) in obj {
                            let type_str = match value_type {
                                serde_json::Value::String(_) => "string",
                                serde_json::Value::Number(_) => "number",
                                serde_json::Value::Bool(_) => "boolean",
                                serde_json::Value::Array(_) => "array",
                                serde_json::Value::Object(_) => "object",
                                serde_json::Value::Null => "null",
                            };
                            debug!("  - {} ({})", key, type_str);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub async fn collect_logs(&self) -> Result<(), LoggerError> {
        // Validate configuration first
        self.config.validate()
            .map_err(|e| LoggerError::ConfigError(e))?;

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

        // Generate and save security report
        let report = SecurityReport::new(&logs);
        let report_path = self.config.output_dir.join(
            format!("security_report_{}.json", Local::now().format("%Y%m%d_%H%M%S"))
        );
        report.save(&report_path)
            .map_err(|e| LoggerError::FileAccessError(e.to_string()))?;

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

        for (category, patterns) in &self.config.log_patterns {
            if self.shutdown.load(Ordering::SeqCst) {
                warn!("Received shutdown signal, stopping log collection");
                break;
            }

            debug!("Processing category: {}", category);
            
            for pattern in patterns {
                if self.shutdown.load(Ordering::SeqCst) {
                    break;
                }

                debug!("Processing pattern: {}", pattern);
                
                let mut cmd = Command::new("log");
                cmd.arg("show")
                   .arg("--predicate")
                   .arg(pattern)
                   .arg("--style")
                   .arg("json");

                // Add time range arguments
                for arg in self.config.get_time_args() {
                    cmd.arg(arg);
                }

                let output = cmd.output()
                    .map_err(|e| LoggerError::CommandError(e))?;

                if !output.status.success() {
                    let error_msg = String::from_utf8_lossy(&output.stderr);
                    error!("Log command failed for pattern '{}': {}", pattern, error_msg);
                    continue;
                }

                let raw_output = String::from_utf8_lossy(&output.stdout);
                
                // Print sample and analyze format
                if !raw_output.is_empty() {
                    if let Some(sample) = raw_output.lines().take(1).next() {
                        debug!("Sample log entry: {}", sample);
                        Self::analyze_log_format(sample)?;
                    }

                    // Save raw output
                    let raw_output_path = self.config.output_dir.join(
                        format!("raw_output_{}_{}.json", category, timestamp)
                    );
                    if let Err(e) = fs::write(&raw_output_path, raw_output.as_bytes()).await {
                        error!("Failed to save raw output: {}", e);
                    }
                }

                match serde_json::from_str::<Vec<LogEntry>>(&raw_output) {
                    Ok(mut entries) => {
                        for entry in &mut entries {
                            entry.set_category(category.clone());
                        }
                        info!("Successfully parsed {} log entries for category {}", entries.len(), category);
                        logs.extend(entries);
                    }
                    Err(e) => {
                        error!("Failed to parse log entries for pattern '{}': {}", pattern, e);
                        if !raw_output.is_empty() {
                            let debug_file = self.config.output_dir.join(
                                format!("debug_log_{}_{}.json", category, timestamp)
                            );
                            if let Err(write_err) = fs::write(&debug_file, raw_output.as_bytes()).await {
                                error!("Failed to save debug file: {}", write_err);
                            }
                        }
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