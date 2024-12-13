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
    
    #[serde(rename = "eventMessage")]
    pub message: String,
    
    #[serde(rename = "processName")]
    pub process: String,
    
    #[serde(rename = "subsystem", default)]
    pub subsystem: Option<String>,
    
    #[serde(rename = "category", default)]
    pub category: Option<String>,
    
    #[serde(rename = "processID")]
    pub pid: Option<FlexibleType>,
    
    #[serde(rename = "threadID")]
    pub thread_id: Option<FlexibleType>,
    
    #[serde(rename = "senderImagePath", default)]
    pub sender_image_path: Option<String>,
    
    #[serde(flatten)]
    pub additional_fields: serde_json::Map<String, Value>,
}

impl Zeroize for LogEntry {
    fn zeroize(&mut self) {
        self.message.zeroize();
        self.process.zeroize();
        if let Some(s) = &mut self.subsystem {
            s.zeroize();
        }
        if let Some(c) = &mut self.category {
            c.zeroize();
        }
        if let Some(path) = &mut self.sender_image_path {
            path.zeroize();
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

impl From<FlexibleType> for String {
    fn from(value: FlexibleType) -> Self {
        match value {
            FlexibleType::String(s) => s,
            FlexibleType::Integer(i) => i.to_string(),
            FlexibleType::Float(f) => f.to_string(),
            FlexibleType::Boolean(b) => b.to_string(),
            FlexibleType::Null => "null".to_string(),
        }
    }
}