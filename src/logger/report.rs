use chrono::{DateTime, Local};
use serde::Serialize;
use std::collections::HashMap;
use crate::logger::models::LogEntry;

#[derive(Debug, Serialize)]
pub struct SecurityReport {
    pub generated_at: DateTime<Local>,
    pub summary: SecuritySummary,
    pub categories: HashMap<String, CategoryStats>,
    pub alerts: Vec<SecurityAlert>,
}

#[derive(Debug, Serialize)]
pub struct SecuritySummary {
    pub total_events: usize,
    pub high_priority_events: usize,
    pub categories_affected: usize,
}

#[derive(Debug, Serialize)]
pub struct CategoryStats {
    pub total_events: usize,
    pub latest_event: Option<DateTime<Local>>,
    pub severity_counts: HashMap<String, usize>,
}

#[derive(Debug, Serialize)]
pub struct SecurityAlert {
    pub timestamp: DateTime<Local>,
    pub category: String,
    pub severity: String,
    pub message: String,
    pub source: String,
}

impl SecurityReport {
    pub fn new(logs: &[LogEntry]) -> Self {
        let mut categories: HashMap<String, CategoryStats> = HashMap::new();
        let mut alerts: Vec<SecurityAlert> = Vec::new();

        // Process logs
        for log in logs {
            let category = log.security_category.clone().unwrap_or_else(|| "unknown".to_string());
            let entry = categories.entry(category.clone()).or_insert(CategoryStats {
                total_events: 0,
                latest_event: None,
                severity_counts: HashMap::new(),
            });

            entry.total_events += 1;
            entry.latest_event = Some(log.timestamp);

            // Check for high-priority events
            if Self::is_high_priority(log) {
                alerts.push(SecurityAlert {
                    timestamp: log.timestamp,
                    category: category.clone(),
                    severity: "HIGH".to_string(),
                    message: log.get_message(),
                    source: log.get_process_name(),
                });
            }
        }

        SecurityReport {
            generated_at: Local::now(),
            summary: SecuritySummary {
                total_events: logs.len(),
                high_priority_events: alerts.len(),
                categories_affected: categories.len(),
            },
            categories,
            alerts,
        }
    }

    fn is_high_priority(log: &LogEntry) -> bool {
        let high_priority_keywords = [
            "violation", "breach", "failed", "blocked", "malware",
            "unauthorized", "suspicious", "attack", "compromise"
        ];

        let message = log.get_message().to_lowercase();
        high_priority_keywords.iter().any(|&keyword| message.contains(keyword))
    }

    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_report_generation() {
        let log = LogEntry {
            timestamp: Utc::now().into(),
            process: Some("test_process".to_string()),
            message: Some("security breach detected".to_string()),
            security_category: Some("security".to_string()),
            subsystem: None,
            category: None,
            pid: None,
            event_type: None,
            format_string: None,
            additional_fields: HashMap::new(),
        };

        let logs = vec![log];
        let report = SecurityReport::new(&logs);

        assert_eq!(report.summary.total_events, 1);
        assert_eq!(report.summary.high_priority_events, 1);
        assert_eq!(report.summary.categories_affected, 1);
    }

    #[test]
    fn test_high_priority_detection() {
        let log = LogEntry {
            timestamp: Utc::now().into(),
            process: Some("test".to_string()),
            message: Some("suspicious activity detected".to_string()),
            security_category: Some("security".to_string()),
            subsystem: None,
            category: None,
            pid: None,
            event_type: None,
            format_string: None,
            additional_fields: HashMap::new(),
        };

        assert!(SecurityReport::is_high_priority(&log));
    }
}