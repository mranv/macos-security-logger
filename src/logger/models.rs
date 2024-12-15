use serde::{Deserialize, Serialize};
use chrono::{DateTime, Local};
use zeroize::Zeroize;
use crate::utils;
use serde_json::Value;
use std::collections::HashMap;

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
    // Base fields that are always present
    #[serde(rename = "timestamp")]
    pub timestamp: DateTime<Local>,
    
    // Process information with multiple possible field names
    #[serde(rename = "processName", alias = "process", alias = "sender", default)]
    pub process: Option<String>,
    
    #[serde(rename = "processIdentifier", alias = "pid", default)]
    pub pid: Option<FlexibleType>,
    
    // Message fields with multiple possible names
    #[serde(rename = "eventMessage", alias = "message", alias = "messageText", default)]
    pub message: Option<String>,
    
    // Subsystem and category information
    #[serde(rename = "subsystem", default)]
    pub subsystem: Option<String>,
    
    #[serde(rename = "category", default)]
    pub category: Option<String>,
    
    // Security specific fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_category: Option<String>,
    
    #[serde(rename = "eventType", default)]
    pub event_type: Option<String>,
    
    #[serde(rename = "formatString", default)]
    pub format_string: Option<String>,
    
    // Store all unknown fields
    #[serde(flatten)]
    pub additional_fields: HashMap<String, Value>,
}

impl LogEntry {
    pub fn set_category(&mut self, category: String) {
        self.security_category = Some(category);
    }

    pub fn get_process_name(&self) -> String {
        self.process.clone()
            .or_else(|| self.additional_fields.get("processName").and_then(|v| v.as_str().map(String::from)))
            .or_else(|| self.additional_fields.get("process").and_then(|v| v.as_str().map(String::from)))
            .unwrap_or_else(|| "unknown".to_string())
    }

    pub fn get_message(&self) -> String {
        self.message.clone()
            .or_else(|| self.format_string.clone())
            .or_else(|| self.additional_fields.get("eventMessage").and_then(|v| v.as_str().map(String::from)))
            .unwrap_or_else(|| "no message".to_string())
    }

    pub fn get_severity(&self) -> String {
        self.additional_fields.get("severity")
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_else(|| "info".to_string())
    }
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
    pub sources: Vec<String>,
    pub categories: Vec<String>,
}

impl LogOutput {
    pub fn new(logs: &[LogEntry]) -> Self {
        use std::collections::HashSet;
        
        // Collect unique sources and categories
        let sources: Vec<String> = logs.iter()
            .map(|log| log.get_process_name())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        let categories: Vec<String> = logs.iter()
            .filter_map(|log| log.security_category.clone())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        Self {
            metadata: OutputMetadata {
                generated_at: Local::now(),
                total_entries: logs.len(),
                host_name: utils::get_hostname(),
                os_version: utils::get_os_version(),
                sources,
                categories,
            },
            logs: logs.to_vec(),
        }
    }
}