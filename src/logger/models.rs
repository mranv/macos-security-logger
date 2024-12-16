use serde::{Deserialize, Serialize};
use chrono::{DateTime, Local};
use zeroize::Zeroize;
// use crate::utils;
use serde_json::Value;
use std::collections::HashMap;
use std::fmt;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum FlexibleType {
    String(String),
    Integer(i64),
    Float(f64),
    Boolean(bool),
    Null,
}

impl fmt::Display for FlexibleType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FlexibleType::String(s) => write!(f, "{}", s),
            FlexibleType::Integer(i) => write!(f, "{}", i),
            FlexibleType::Float(fl) => write!(f, "{}", fl),
            FlexibleType::Boolean(b) => write!(f, "{}", b),
            FlexibleType::Null => write!(f, "null"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SecurityEvent {
    pub timestamp: DateTime<Local>,
    pub event_type: String,
    pub level: SecurityLevel,
    pub source: String,
    pub details: String,
    pub category: String,
    pub raw_data: Option<Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum SecurityLevel {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LogEntry {
    #[serde(rename = "timestamp")]
    pub timestamp: DateTime<Local>,
    
    #[serde(rename = "processName", alias = "process", alias = "sender", default)]
    pub process: Option<String>,
    
    #[serde(rename = "processIdentifier", alias = "pid", default)]
    pub pid: Option<FlexibleType>,
    
    #[serde(rename = "eventMessage", alias = "message", alias = "messageText", default)]
    pub message: Option<String>,
    
    #[serde(rename = "subsystem", default)]
    pub subsystem: Option<String>,
    
    #[serde(rename = "category", default)]
    pub category: Option<String>,
    
    #[serde(rename = "eventType", default)]
    pub event_type: Option<String>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_level: Option<SecurityLevel>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_category: Option<String>,
    
    #[serde(rename = "formatString", default)]
    pub format_string: Option<String>,
    
    #[serde(flatten)]
    pub additional_fields: HashMap<String, Value>,
}

impl LogEntry {
    pub fn to_security_event(&self) -> SecurityEvent {
        SecurityEvent {
            timestamp: self.timestamp,
            event_type: self.event_type.clone().unwrap_or_else(|| "unknown".to_string()),
            level: self.determine_security_level(),
            source: self.get_process_name(),
            details: self.get_message(),
            category: self.security_category.clone().unwrap_or_else(|| "general".to_string()),
            raw_data: Some(serde_json::to_value(self.additional_fields.clone()).unwrap_or_default()),
        }
    }

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

    pub fn get_subsystem(&self) -> String {
        self.subsystem.clone()
            .unwrap_or_else(|| "unknown".to_string())
    }

    pub fn determine_security_level(&self) -> SecurityLevel {
        let message = self.get_message().to_lowercase();
        
        if message.contains("critical") || 
           message.contains("breach") || 
           message.contains("violation") {
            SecurityLevel::Critical
        } else if message.contains("error") || 
                  message.contains("failed") || 
                  message.contains("denied") {
            SecurityLevel::High
        } else if message.contains("warning") || 
                  message.contains("modified") {
            SecurityLevel::Medium
        } else if message.contains("notice") || 
                  message.contains("info") {
            SecurityLevel::Low
        } else {
            SecurityLevel::Info
        }
    }

    pub fn is_security_relevant(&self) -> bool {
        let security_keywords = [
            "security", "breach", "violation", "attack", "malware",
            "unauthorized", "permission", "access", "firewall", "blocked",
            "encryption", "certificate", "authentication", "login", "password",
            "failed", "error", "warning", "critical", "suspicious"
        ];

        let message = self.get_message().to_lowercase();
        security_keywords.iter().any(|&keyword| message.contains(keyword))
    }

    pub fn get_context(&self) -> HashMap<String, String> {
        let mut context = HashMap::new();
        
        // Add process information
        if let Some(pid) = &self.pid {
            context.insert("pid".to_string(), pid.to_string());
        }
        
        // Add subsystem
        if let Some(subsystem) = &self.subsystem {
            context.insert("subsystem".to_string(), subsystem.clone());
        }
        
        // Add category
        if let Some(category) = &self.category {
            context.insert("category".to_string(), category.clone());
        }

        // Add any additional relevant fields
        for (key, value) in &self.additional_fields {
            if let Some(str_value) = value.as_str() {
                context.insert(key.clone(), str_value.to_string());
            }
        }

        context
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
        if let Some(f) = &mut self.format_string {
            f.zeroize();
        }
    }
}

#[derive(Debug, Serialize)]
pub struct LogMetadata {
    pub timestamp: DateTime<Local>,
    pub total_entries: usize,
    pub security_events: usize,
    pub critical_events: usize,
    pub categories: Vec<String>,
    pub sources: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct LogOutput {
    pub metadata: LogMetadata,
    pub events: Vec<SecurityEvent>,
}

impl LogOutput {
    pub fn new(logs: &[LogEntry]) -> Self {
        use std::collections::HashSet;
        
        let security_events: Vec<SecurityEvent> = logs.iter()
            .filter(|log| log.is_security_relevant())
            .map(|log| log.to_security_event())
            .collect();

        let categories: Vec<String> = logs.iter()
            .filter_map(|log| log.security_category.clone())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        let sources: Vec<String> = logs.iter()
            .map(|log| log.get_process_name())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        let critical_count = security_events.iter()
            .filter(|event| matches!(event.level, SecurityLevel::Critical))
            .count();

        Self {
            metadata: LogMetadata {
                timestamp: Local::now(),
                total_entries: logs.len(),
                security_events: security_events.len(),
                critical_events: critical_count,
                categories,
                sources,
            },
            events: security_events,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_security_level_determination() {
        let mut log = LogEntry {
            timestamp: Utc::now().into(),
            process: Some("test".to_string()),
            message: Some("Critical security breach detected".to_string()),
            security_category: Some("security".to_string()),
            subsystem: None,
            category: None,
            pid: None,
            event_type: None,
            security_level: None,
            format_string: None,
            additional_fields: HashMap::new(),
        };

        assert!(matches!(log.determine_security_level(), SecurityLevel::Critical));

        log.message = Some("Warning: configuration modified".to_string());
        assert!(matches!(log.determine_security_level(), SecurityLevel::Medium));
    }

    #[test]
    fn test_security_relevance() {
        let log = LogEntry {
            timestamp: Utc::now().into(),
            process: Some("test".to_string()),
            message: Some("Security breach detected".to_string()),
            security_category: Some("security".to_string()),
            subsystem: None,
            category: None,
            pid: None,
            event_type: None,
            security_level: None,
            format_string: None,
            additional_fields: HashMap::new(),
        };

        assert!(log.is_security_relevant());
    }

    #[test]
    fn test_log_entry_context() {
        let mut additional_fields = HashMap::new();
        additional_fields.insert(
            "source_ip".to_string(), 
            Value::String("192.168.1.1".to_string())
        );

        let log = LogEntry {
            timestamp: Utc::now().into(),
            process: Some("test".to_string()),
            message: Some("Test message".to_string()),
            security_category: Some("security".to_string()),
            subsystem: Some("test_subsystem".to_string()),
            category: Some("test_category".to_string()),
            pid: Some(FlexibleType::Integer(123)),
            event_type: None,
            security_level: None,
            format_string: None,
            additional_fields,
        };

        let context = log.get_context();
        assert_eq!(context.get("pid").unwrap(), "123");
        assert_eq!(context.get("subsystem").unwrap(), "test_subsystem");
        assert_eq!(context.get("source_ip").unwrap(), "192.168.1.1");
    }
}