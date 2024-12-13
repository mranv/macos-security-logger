use serde::{Deserialize, Serialize};
use chrono::{DateTime, Local};
use zeroize::Zeroize;
use crate::utils;
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum FlexibleType {
    String(String),
    Integer(i64),
    Float(f64),
    Boolean(bool),
    Null,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LogEntry {
    #[serde(rename = "timestamp")]
    pub timestamp: DateTime<Local>,
    
    #[serde(rename = "eventMessage", alias = "message", default)]
    pub message: Option<String>,
    
    #[serde(rename = "processName", alias = "process", default)]
    pub process: Option<String>,
    
    #[serde(rename = "subsystem", default)]
    pub subsystem: Option<String>,
    
    #[serde(rename = "category", default)]
    pub category: Option<String>,
    
    #[serde(rename = "processID", alias = "pid", default)]
    pub pid: Option<FlexibleType>,
    
    #[serde(rename = "threadID", alias = "tid", default)]
    pub thread_id: Option<FlexibleType>,
    
    #[serde(flatten)]
    pub additional_fields: serde_json::Map<String, Value>,
}

impl Zeroize for LogEntry {
    fn zeroize(&mut self) {
        if let Some(msg) = &mut self.message {
            msg.zeroize();
        }
        if let Some(proc) = &mut self.process {
            proc.zeroize();
        }
        if let Some(s) = &mut self.subsystem {
            s.zeroize();
        }
        if let Some(c) = &mut self.category {
            c.zeroize();
        }
    }
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