use serde::{Deserialize, Serialize};
use chrono::{DateTime, Local};
use zeroize::Zeroize;

#[derive(Debug, Serialize, Deserialize, Zeroize)]
pub struct LogEntry {
    pub timestamp: DateTime<Local>,
    pub event_type: String,
    pub process: String,
    pub message: String,
    pub pid: Option<i32>,
    pub facility: Option<String>,
    pub priority: Option<String>,
    #[zeroize(skip)]
    pub metadata: Option<LogMetadata>,
}

#[derive(Debug, Serialize, Deserialize)]
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