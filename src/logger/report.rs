use chrono::{DateTime, Local};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use crate::logger::models::LogEntry;

#[derive(Debug, Serialize)]
pub struct SecurityReport {
    pub generated_at: DateTime<Local>,
    pub summary: SecuritySummary,
    pub categories: HashMap<String, CategoryStats>,
    pub alerts: Vec<SecurityAlert>,
    pub timeline: SecurityTimeline,
    pub threat_analysis: ThreatAnalysis,
    pub system_status: SystemSecurityStatus,
}

#[derive(Debug, Serialize)]
pub struct SecuritySummary {
    pub total_events: usize,
    pub high_priority_events: usize,
    pub categories_affected: usize,
    pub unique_processes: usize,
    pub unique_subsystems: usize,
    pub critical_alerts: usize,
    pub risk_score: f32,
}

#[derive(Debug, Serialize)]
pub struct CategoryStats {
    pub total_events: usize,
    pub latest_event: Option<DateTime<Local>>,
    pub severity_counts: HashMap<String, usize>,
    pub unique_sources: HashSet<String>,
    pub top_events: Vec<EventSummary>,
    pub trend: TrendAnalysis,
}

#[derive(Debug, Serialize)]
pub struct SecurityAlert {
    pub timestamp: DateTime<Local>,
    pub category: String,
    pub severity: String,
    pub message: String,
    pub source: String,
    pub context: AlertContext,
    pub recommendation: String,
    pub related_events: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct AlertContext {
    pub subsystem: Option<String>,
    pub process_info: ProcessInfo,
    pub related_files: Vec<String>,
    pub network_info: Option<NetworkInfo>,
}

#[derive(Debug, Serialize)]
pub struct ProcessInfo {
    pub pid: Option<String>,
    pub path: Option<String>,
    pub user: Option<String>,
    pub command: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct NetworkInfo {
    pub source_ip: Option<String>,
    pub destination_ip: Option<String>,
    pub port: Option<u16>,
    pub protocol: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SecurityTimeline {
    pub events: Vec<TimelineEvent>,
    pub patterns: Vec<TimelinePattern>,
}

#[derive(Debug, Serialize)]
pub struct TimelineEvent {
    pub timestamp: DateTime<Local>,
    pub event_type: String,
    pub description: String,
    pub severity: String,
}

#[derive(Debug, Serialize)]
pub struct TimelinePattern {
    pub pattern_type: String,
    pub frequency: usize,
    pub first_seen: DateTime<Local>,
    pub last_seen: DateTime<Local>,
}

#[derive(Debug, Serialize)]
pub struct ThreatAnalysis {
    pub potential_threats: Vec<ThreatIndicator>,
    pub anomalies: Vec<AnomalyDetail>,
    pub risk_factors: Vec<RiskFactor>,
}

#[derive(Debug, Serialize)]
pub struct SystemSecurityStatus {
    pub sip_status: bool,
    pub firewall_status: bool,
    pub disk_encryption_status: bool,
    pub xprotect_version: Option<String>,
    pub security_updates: Vec<UpdateInfo>,
}

#[derive(Debug, Serialize)]
pub struct EventSummary {
    pub event_type: String,
    pub count: usize,
    pub last_seen: DateTime<Local>,
    pub severity: String,
}

#[derive(Debug, Serialize)]
pub struct TrendAnalysis {
    pub trend_direction: String,
    pub percentage_change: f32,
    pub period: String,
}

#[derive(Debug, Serialize)]
pub struct ThreatIndicator {
    pub indicator_type: String,
    pub confidence: f32,
    pub evidence: Vec<String>,
    pub recommendation: String,
}

#[derive(Debug, Serialize)]
pub struct AnomalyDetail {
    pub anomaly_type: String,
    pub description: String,
    pub severity: String,
    pub affected_components: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct RiskFactor {
    pub factor: String,
    pub impact_level: String,
    pub mitigation_status: String,
}

#[derive(Debug, Serialize)]
pub struct UpdateInfo {
    pub update_name: String,
    pub status: String,
    pub last_checked: DateTime<Local>,
}

impl SecurityReport {
    pub fn new(logs: &[LogEntry]) -> Self {
        let mut categories: HashMap<String, CategoryStats> = HashMap::new();
        let mut alerts: Vec<SecurityAlert> = Vec::new();
        let mut unique_processes = HashSet::new();
        let mut unique_subsystems = HashSet::new();
        let mut timeline_events = Vec::new();

        // Process logs
        for log in logs {
            let category = log.security_category.clone().unwrap_or_else(|| "unknown".to_string());
            Self::process_log_entry(
                log, 
                &mut categories, 
                &mut alerts, 
                &mut unique_processes, 
                &mut unique_subsystems,
                &mut timeline_events
            );
        }

        let threat_analysis = Self::analyze_threats(logs);
        let system_status = Self::check_system_status(logs);
        let risk_score = Self::calculate_risk_score(&categories, &alerts);

        SecurityReport {
            generated_at: Local::now(),
            summary: SecuritySummary {
                total_events: logs.len(),
                high_priority_events: alerts.len(),
                categories_affected: categories.len(),
                unique_processes: unique_processes.len(),
                unique_subsystems: unique_subsystems.len(),
                critical_alerts: alerts.iter().filter(|a| a.severity == "CRITICAL").count(),
                risk_score,
            },
            categories,
            alerts,
            timeline: SecurityTimeline {
                events: timeline_events,
                patterns: Self::analyze_patterns(logs),
            },
            threat_analysis,
            system_status,
        }
    }

    fn process_log_entry(
        log: &LogEntry,
        categories: &mut HashMap<String, CategoryStats>,
        alerts: &mut Vec<SecurityAlert>,
        unique_processes: &mut HashSet<String>,
        unique_subsystems: &mut HashSet<String>,
        timeline_events: &mut Vec<TimelineEvent>,
    ) {
        let category = log.security_category.clone().unwrap_or_else(|| "unknown".to_string());
        
        // Update category stats
        let entry = categories.entry(category.clone()).or_insert(CategoryStats {
            total_events: 0,
            latest_event: None,
            severity_counts: HashMap::new(),
            unique_sources: HashSet::new(),
            top_events: Vec::new(),
            trend: TrendAnalysis {
                trend_direction: "stable".to_string(),
                percentage_change: 0.0,
                period: "1h".to_string(),
            },
        });

        entry.total_events += 1;
        entry.latest_event = Some(log.timestamp);
        entry.unique_sources.insert(log.get_process_name());

        // Track unique processes and subsystems
        if let Some(process) = &log.process {
            unique_processes.insert(process.clone());
        }
        if let Some(subsystem) = &log.subsystem {
            unique_subsystems.insert(subsystem.clone());
        }

        // Create timeline event
        timeline_events.push(TimelineEvent {
            timestamp: log.timestamp,
            event_type: log.event_type.clone().unwrap_or_else(|| "unknown".to_string()),
            description: log.get_message(),
            severity: Self::determine_severity(log),
        });

        // Check for high-priority events
        if Self::is_high_priority(log) {
            alerts.push(Self::create_security_alert(log, &category));
        }
    }

    fn is_high_priority(log: &LogEntry) -> bool {
        let high_priority_keywords = [
            "violation", "breach", "failed", "blocked", "malware",
            "unauthorized", "suspicious", "attack", "compromise",
            "exploit", "overflow", "injection", "bypass", "escalation",
            "rootkit", "backdoor", "ransomware", "privilege"
        ];

        let message = log.get_message().to_lowercase();
        high_priority_keywords.iter().any(|&keyword| message.contains(keyword))
    }

    fn determine_severity(log: &LogEntry) -> String {
        let message = log.get_message().to_lowercase();
        
        if message.contains("critical") || message.contains("breach") {
            "CRITICAL".to_string()
        } else if message.contains("error") || message.contains("failed") {
            "HIGH".to_string()
        } else if message.contains("warning") {
            "MEDIUM".to_string()
        } else {
            "LOW".to_string()
        }
    }

    fn create_security_alert(log: &LogEntry, category: &str) -> SecurityAlert {
        SecurityAlert {
            timestamp: log.timestamp,
            category: category.to_string(),
            severity: Self::determine_severity(log),
            message: log.get_message(),
            source: log.get_process_name(),
            context: AlertContext {
                subsystem: log.subsystem.clone(),
                process_info: ProcessInfo {
                    pid: log.pid.as_ref().map(|p| p.to_string()),
                    path: None,
                    user: None,
                    command: None,
                },
                related_files: Vec::new(),
                network_info: None,
            },
            recommendation: "Investigate and verify security status".to_string(),
            related_events: Vec::new(),
        }
    }

    fn analyze_threats(logs: &[LogEntry]) -> ThreatAnalysis {
        let mut threats = Vec::new();
        let mut anomalies = Vec::new();
        let mut risk_factors = Vec::new();

        // Group logs by source
        let mut source_counts: HashMap<String, usize> = HashMap::new();
        let mut source_patterns: HashMap<String, Vec<&LogEntry>> = HashMap::new();

        for log in logs {
            let source = log.get_process_name();
            *source_counts.entry(source.clone()).or_insert(0) += 1;
            source_patterns.entry(source).or_default().push(log);
        }

        // Analyze patterns and create threat indicators
        for (source, logs) in source_patterns {
            let high_severity_count = logs.iter()
                .filter(|log| Self::determine_severity(log) == "CRITICAL")
                .count();

            if high_severity_count > 0 {
                threats.push(ThreatIndicator {
                    indicator_type: "Critical Events".to_string(),
                    confidence: 0.9,
                    evidence: logs.iter().map(|log| log.get_message()).collect(),
                    recommendation: format!("Investigate critical events from {}", source),
                });
            }

            // Check for anomalies
            if logs.len() > 10 {
                anomalies.push(AnomalyDetail {
                    anomaly_type: "High Frequency".to_string(),
                    description: format!("High event frequency from {}", source),
                    severity: "MEDIUM".to_string(),
                    affected_components: vec![source.clone()],
                });
            }

            // Assess risk factors
            let error_rate = logs.iter()
                .filter(|log| log.get_message().to_lowercase().contains("error"))
                .count() as f32 / logs.len() as f32;

            if error_rate > 0.5 {
                risk_factors.push(RiskFactor {
                    factor: format!("High Error Rate - {}", source),
                    impact_level: "HIGH".to_string(),
                    mitigation_status: "Open".to_string(),
                });
            }
        }

        ThreatAnalysis {
            potential_threats: threats,
            anomalies,
            risk_factors,
        }
    }

    fn analyze_patterns(logs: &[LogEntry]) -> Vec<TimelinePattern> {
        let mut patterns = HashMap::new();

        // Group by event type
        for log in logs {
            let event_type = log.event_type.clone().unwrap_or_else(|| "unknown".to_string());
            patterns.entry(event_type)
                .or_insert_with(Vec::new)
                .push(log);
        }

        // Create patterns
        patterns.into_iter()
            .filter(|(_, events)| !events.is_empty())
            .map(|(pattern_type, events)| {
                TimelinePattern {
                    pattern_type,
                    frequency: events.len(),
                    first_seen: events.iter()
                        .map(|e| e.timestamp)
                        .min()
                        .unwrap_or_else(Local::now),
                    last_seen: events.iter()
                        .map(|e| e.timestamp)
                        .max()
                        .unwrap_or_else(Local::now),
                }
            })
            .collect()
    }

    fn check_system_status(logs: &[LogEntry]) -> SystemSecurityStatus {
        let mut status = SystemSecurityStatus {
            sip_status: true,
            firewall_status: true,
            disk_encryption_status: true,
            xprotect_version: None,
            security_updates: Vec::new(),
        };

        for log in logs {
            let message = log.get_message().to_lowercase();
            
            if message.contains("sip") && message.contains("disabled") {
                status.sip_status = false;
            }
            if message.contains("firewall") && message.contains("disabled") {
                status.firewall_status = false;
            }
            if message.contains("filevault") && message.contains("disabled") {
                status.disk_encryption_status = false;
            }
            if message.contains("xprotect") && message.contains("version") {
                status.xprotect_version = Some(format!("Updated at {}", log.timestamp));
            }
            if message.contains("security update") {
                status.security_updates.push(UpdateInfo {
                    update_name: log.get_message(),
                    status: "Pending".to_string(),
                    last_checked: log.timestamp,
                });
            }
        }

        status
    }

    fn calculate_risk_score(
        categories: &HashMap<String, CategoryStats>,
        alerts: &[SecurityAlert],
    ) -> f32 {
        let mut score = 0.0;

        // Base score from categories
        for (_, stats) in categories {
            score += stats.total_events as f32 * 0.1;
            
            // Add weight for severity
            if let Some(critical_count) = stats.severity_counts.get("CRITICAL") {
                score += *critical_count as f32 * 0.5;
            }
            if let Some(high_count) = stats.severity_counts.get("HIGH") {
                score += *high_count as f32 * 0.3;
            }
        }

        // Add score for alerts
        for alert in alerts {
            match alert.severity.as_str() {
                "CRITICAL" => score += 2.0,
                "HIGH" => score += 1.5,
                "MEDIUM" => score += 1.0,
                "LOW" => score += 0.5,
                _ => score += 0.1,
            }

            // Additional weight for specific alert contexts
            if let Some(network_info) = &alert.context.network_info {
                score += 0.5; // Network-related issues are higher risk
            }

            // Check for multiple affected components
            if !alert.context.related_files.is_empty() {
                score += 0.3 * alert.context.related_files.len() as f32;
            }

            // Time-based risk adjustment (newer events have higher weight)
            let age = Local::now()
                .signed_duration_since(alert.timestamp)
                .num_hours();
            if age < 1 {
                score += 0.5; // Events in last 1 hour
            } else if age < 3 {
                score += 0.3; // Events in last 3 hour
            }
        }

        // Consider unique sources impact
        let unique_sources: HashSet<_> = alerts.iter()
            .map(|alert| &alert.source)
            .collect();
        if unique_sources.len() > 5 {
            score += 1.0; // Multiple sources indicate broader impact
        }

        // Risk multipliers for specific conditions
        if alerts.iter().any(|a| a.message.to_lowercase().contains("breach")) {
            score *= 1.5; // 50% increase for confirmed breaches
        }
        if alerts.iter().any(|a| a.message.to_lowercase().contains("malware")) {
            score *= 1.3; // 30% increase for malware detection
        }

        // Normalize score to 0-10 range with exponential scaling
        let normalized_score = (score * 10.0 / (score + 10.0)).min(10.0);
        
        // Round to 2 decimal places
        (normalized_score * 100.0).round() / 100.0
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
    fn test_risk_score_calculation() {
        // Create test categories
        let mut categories = HashMap::new();
        let mut severity_counts = HashMap::new();
        severity_counts.insert("CRITICAL".to_string(), 2);
        severity_counts.insert("HIGH".to_string(), 3);
        
        categories.insert("test".to_string(), CategoryStats {
            total_events: 5,
            latest_event: Some(Local::now()),
            severity_counts,
            unique_sources: HashSet::new(),
            top_events: Vec::new(),
            trend: TrendAnalysis {
                trend_direction: "stable".to_string(),
                percentage_change: 0.0,
                period: "1h".to_string(),
            },
        });

        // Create test alerts
        let alerts = vec![
            SecurityAlert {
                timestamp: Local::now(),
                category: "test".to_string(),
                severity: "CRITICAL".to_string(),
                message: "Security breach detected".to_string(),
                source: "test_source_1".to_string(),
                context: AlertContext {
                    subsystem: None,
                    process_info: ProcessInfo {
                        pid: None,
                        path: None,
                        user: None,
                        command: None,
                    },
                    related_files: vec!["test_file.txt".to_string()],
                    network_info: Some(NetworkInfo {
                        source_ip: Some("192.168.1.1".to_string()),
                        destination_ip: None,
                        port: None,
                        protocol: None,
                    }),
                },
                recommendation: "Investigate immediately".to_string(),
                related_events: Vec::new(),
            },
            SecurityAlert {
                timestamp: Local::now(),
                category: "test".to_string(),
                severity: "HIGH".to_string(),
                message: "Malware activity detected".to_string(),
                source: "test_source_2".to_string(),
                context: AlertContext {
                    subsystem: None,
                    process_info: ProcessInfo {
                        pid: None,
                        path: None,
                        user: None,
                        command: None,
                    },
                    related_files: Vec::new(),
                    network_info: None,
                },
                recommendation: "Run anti-malware scan".to_string(),
                related_events: Vec::new(),
            },
        ];

        let score = SecurityReport::calculate_risk_score(&categories, &alerts);
        
        // Score should be between 0 and 10
        assert!(score >= 0.0 && score <= 10.0);
        
        // Score should be high due to critical and high severity alerts
        assert!(score > 5.0);
    }
}