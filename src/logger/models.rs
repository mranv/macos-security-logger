use serde::{Deserialize, Serialize};
use chrono::{DateTime, Local};
use zeroize::Zeroize;
use crate::utils;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LogEntry {
    #[serde(rename = "timestamp")]
    pub timestamp: DateTime<Local>,
    #[serde(rename = "eventMessage")]
    pub message: String,
    #[serde(rename = "processName")]
    pub process: String,
    #[serde(rename = "subsystem", default)]
    pub subsystem: String,
    #[serde(rename = "category", default)]
    pub category: String,
    #[serde(rename = "processID")]
    pub pid: Option<i32>,
    #[serde(rename = "threadID")]
    pub thread_id: Option<String>,
    #[serde(rename = "senderImagePath", default)]
    pub sender_image_path: Option<String>,
    #[serde(flatten)]
    pub additional_fields: serde_json::Value,
}

impl Zeroize for LogEntry {
    fn zeroize(&mut self) {
        self.message.zeroize();
        self.process.zeroize();
        self.subsystem.zeroize();
        self.category.zeroize();
        if let Some(path) = &mut self.sender_image_path {
            path.zeroize();
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LogMetadata {
    pub source_file: Option<String>,
    pub line_number: Option<u32>,
    pub thread_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LogOutput {
    pub metadata: OutputMetadata,
    pub logs: Vec<LogEntry>,
}

#[derive(Debug, Serialize)]
pub struct OutputMetadata {
    pub generated_at: DateTime<Local>,
    pub total_entries: usize,
    pub host_name: String,
    pub os_version: String,
}

impl LogOutput {
    pub fn new(logs: &[LogEntry]) -> Self {
        Self {
            metadata: OutputMetadata {
                generated_at: Local::now(),
                total_entries: logs.len(),
                host_name: utils::get_hostname(),
                os_version: utils::get_os_version(),
            },
            logs: logs.to_vec(),
        }
    }
}