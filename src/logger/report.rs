use chrono::{DateTime, Local};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use crate::logger::models::{LogEntry, SecurityLevel};


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
        // Update category stats
        let entry = categories.entry(log.security_category.clone().unwrap_or_else(|| "unknown".to_string()))
            .or_insert(CategoryStats {
                total_events: 0,
                latest_event: None,
                severity_counts: HashMap::new(),
                unique_sources: HashSet::new(),
                top_events: Vec::new(),
                trend: TrendAnalysis {
                    trend_direction: "stable".to_string(),
                    percentage_change: 0.0,
                    period: "24h".to_string(),
                },
            });

        entry.total_events += 1;
        entry.latest_event = Some(log.timestamp);
        entry.unique_sources.insert(log.get_process_name());

        let severity = Self::determine_severity(log);
        *entry.severity_counts.entry(severity.clone()).or_insert(0) += 1;

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
            severity: severity.clone(),
        });

        // Check for high-priority events
        if Self::is_high_priority(log) {
            alerts.push(Self::create_security_alert(log));
        }
    }

    fn is_high_priority(log: &LogEntry) -> bool {
        const HIGH_PRIORITY_KEYWORDS: [&str; 18] = [
            "violation", "breach", "failed", "blocked", "malware",
            "unauthorized", "suspicious", "attack", "compromise",
            "exploit", "overflow", "injection", "bypass", "escalation",
            "rootkit", "backdoor", "ransomware", "privilege"
        ];

        let message = log.get_message().to_lowercase();
        HIGH_PRIORITY_KEYWORDS.iter().any(|&keyword| message.contains(keyword))
    }

    fn determine_severity(log: &LogEntry) -> String {
        // First check the security_level if present
        if let Some(level) = &log.security_level {
            return match level {
                SecurityLevel::Critical => "CRITICAL".to_string(),
                SecurityLevel::High => "HIGH".to_string(),
                SecurityLevel::Medium => "MEDIUM".to_string(),
                SecurityLevel::Low => "LOW".to_string(),
                SecurityLevel::Info => "LOW".to_string(),
            };
        }
        
        // If no security_level set, analyze message content
        let message = log.get_message().to_lowercase();
        if message.contains("critical") || 
           message.contains("breach") || 
           message.contains("malware") {
            "CRITICAL".to_string()
        } else if message.contains("error") || message.contains("failed") {
            "HIGH".to_string()
        } else if message.contains("warning") {
            "MEDIUM".to_string()
        } else {
            "LOW".to_string()
        }
    }

    fn create_security_alert(log: &LogEntry) -> SecurityAlert {
        SecurityAlert {
            timestamp: log.timestamp,
            category: log.security_category.clone()
                .unwrap_or_else(|| "unknown".to_string()),
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
            recommendation: Self::generate_recommendation(log),
            related_events: Vec::new(),
        }
    }

    fn generate_recommendation(log: &LogEntry) -> String {
        let message = log.get_message().to_lowercase();
        if message.contains("malware") {
            "Isolate affected system and run full security scan".to_string()
        } else if message.contains("breach") {
            "Initiate security incident response and investigate breach".to_string()
        } else if message.contains("unauthorized") {
            "Review access logs and update security policies".to_string()
        } else {
            "Investigate and verify security status".to_string()
        }
    }

    fn analyze_threats(logs: &[LogEntry]) -> ThreatAnalysis {
        let mut threats = Vec::new();
        let mut anomalies = Vec::new();
        let mut risk_factors = Vec::new();
    
        for log in logs {
            let message = log.get_message().to_lowercase();
            let severity = log.security_level.as_ref().unwrap_or(&SecurityLevel::Low);
    
            // Detect potential threats based on severity
            match severity {
                SecurityLevel::Critical | SecurityLevel::High => {
                    threats.push(ThreatIndicator {
                        indicator_type: if message.contains("malware") {
                            "Malware Detection".to_string()
                        } else if message.contains("login") {
                            "Authentication Threat".to_string()
                        } else {
                            "Security Violation".to_string()
                        },
                        confidence: 0.9,
                        evidence: vec![log.get_message()],
                        recommendation: match log.security_level {
                            Some(SecurityLevel::Critical) => "Immediate action required",
                            Some(SecurityLevel::High) => "Investigate urgently",
                            _ => "Review and monitor",
                        }.to_string(),
                    });
                }
                _ => {}
            }
    
            // Detect anomalies
            if message.contains("failed") || message.contains("multiple") {
                anomalies.push(AnomalyDetail {
                    anomaly_type: "Repeated Failure".to_string(),
                    description: log.get_message(),
                    severity: "HIGH".to_string(),
                    affected_components: vec![log.get_process_name()],
                });
            }
    
            // Add risk factors
            if let Some(SecurityLevel::High) = log.security_level {
                risk_factors.push(RiskFactor {
                    factor: format!("High Severity Event - {}", log.get_process_name()),
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

    fn analyze_source_patterns(
        source: &str,
        logs: &[&LogEntry],
        threats: &mut Vec<ThreatIndicator>,
        anomalies: &mut Vec<AnomalyDetail>,
        risk_factors: &mut Vec<RiskFactor>,
    ) {
        // Check for high frequency
        if logs.len() > 10 {
            anomalies.push(AnomalyDetail {
                anomaly_type: "High Frequency".to_string(),
                description: format!("High event frequency from source: {}", source),
                severity: "MEDIUM".to_string(),
                affected_components: vec![source.to_string()],
            });
        }

        // Analyze error patterns
        let error_logs: Vec<_> = logs.iter()
            .filter(|log| log.get_message().to_lowercase().contains("error"))
            .collect();

        if !error_logs.is_empty() {
            risk_factors.push(RiskFactor {
                factor: format!("Error Pattern - {}", source),
                impact_level: if error_logs.len() > 5 { "HIGH" } else { "MEDIUM" }.to_string(),
                mitigation_status: "Open".to_string(),
            });
        }

        // Check for critical events
        let critical_logs: Vec<_> = logs.iter()
            .filter(|log| Self::determine_severity(log) == "CRITICAL")
            .collect();

        if !critical_logs.is_empty() {
            threats.push(ThreatIndicator {
                indicator_type: "Critical Events".to_string(),
                confidence: 0.9,
                evidence: critical_logs.iter().map(|log| log.get_message()).collect(),
                recommendation: format!("Investigate critical events from {}", source),
            });
        }
    }

    fn analyze_patterns(logs: &[LogEntry]) -> Vec<TimelinePattern> {
        let mut patterns: HashMap<String, Vec<&LogEntry>> = HashMap::new();

        // Group by event type
        for log in logs {
            let event_type = log.event_type.clone().unwrap_or_else(|| "unknown".to_string());
            patterns.entry(event_type).or_default().push(log);
        }

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
                    status: if message.contains("installed") {
                        "Installed".to_string()
                    } else if message.contains("failed") {
                        "Failed".to_string()
                    } else {
                        "Pending".to_string()
                    },
                    last_checked: log.timestamp,
                });
            }
            
            // Check for security policy violations
            if message.contains("policy violation") || message.contains("compliance failure") {
                status.sip_status = false;
            }

            // Check for network security status
            if message.contains("network protection") && message.contains("disabled") {
                status.firewall_status = false;
            }

            // Monitor encryption status changes
            if message.contains("encryption") && message.contains("compromised") {
                status.disk_encryption_status = false;
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
            for (severity, count) in &stats.severity_counts {
                let severity_weight = match severity.as_str() {
                    "CRITICAL" => 0.5,
                    "HIGH" => 0.3,
                    "MEDIUM" => 0.2,
                    "LOW" => 0.1,
                    _ => 0.0,
                };
                score += *count as f32 * severity_weight;
            }
        }

        // Add score for alerts
        for alert in alerts {
            let alert_weight = match alert.severity.as_str() {
                "CRITICAL" => 2.0,
                "HIGH" => 1.5,
                "MEDIUM" => 1.0,
                "LOW" => 0.5,
                _ => 0.1,
            };
            score += alert_weight;

            // Additional risk factors
            if alert.context.network_info.is_some() {
                score += 0.5; // Network-related issues
            }
            score += alert.context.related_files.len() as f32 * 0.3; // Multiple affected files
            
            // Time-based risk factors
            let age_hours = Local::now()
                .signed_duration_since(alert.timestamp)
                .num_hours();
            if age_hours < 24 {
                score += 0.5; // Recent events are higher risk
            }
        }

        // Risk multipliers for specific conditions
        let threat_multiplier = if alerts.iter().any(|a| {
            let msg = a.message.to_lowercase();
            msg.contains("breach") || msg.contains("malware") || msg.contains("compromise")
        }) {
            1.5 // 50% increase for severe threats
        } else {
            1.0
        };

        // Calculate final score with multiplier and normalize to 0-10 range
        let normalized_score = (score * threat_multiplier * 10.0 / (score + 10.0)).min(10.0);
        (normalized_score * 100.0).round() / 100.0 // Round to 2 decimal places
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
    use crate::logger::models::{SecurityLevel, FlexibleType};

    #[test]
    fn test_system_status() {
        let logs = vec![
            LogEntry {
                timestamp: Utc::now().into(),
                process: Some("system".to_string()),
                message: Some("SIP has been disabled".to_string()),
                security_category: Some("system".to_string()),
                security_level: Some(SecurityLevel::High),
                subsystem: None,
                category: None,
                pid: None,
                event_type: None,
                format_string: None,
                additional_fields: HashMap::new(),
            },
            LogEntry {
                timestamp: Utc::now().into(),
                process: Some("system".to_string()),
                message: Some("FileVault encryption enabled".to_string()),
                security_category: Some("system".to_string()),
                security_level: Some(SecurityLevel::Info),
                subsystem: None,
                category: None,
                pid: None,
                event_type: None,
                format_string: None,
                additional_fields: HashMap::new(),
            },
        ];

        let status = SecurityReport::check_system_status(&logs);
        assert!(!status.sip_status); // SIP should be disabled
        assert!(status.disk_encryption_status); // FileVault should be enabled
    }

    #[test]
    fn test_risk_score_calculation() {
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
                period: "24h".to_string(),
            },
        });

        let alerts = vec![SecurityAlert {
            timestamp: Local::now(),
            category: "test".to_string(),
            severity: "CRITICAL".to_string(),
            message: "Security breach detected".to_string(),
            source: "test".to_string(),
            context: AlertContext {
                subsystem: None,
                process_info: ProcessInfo {
                    pid: None,
                    path: None,
                    user: None,
                    command: None,
                },
                related_files: vec!["test.txt".to_string()],
                network_info: Some(NetworkInfo {
                    source_ip: Some("192.168.1.1".to_string()),
                    destination_ip: None,
                    port: None,
                    protocol: None,
                }),
            },
            recommendation: "Investigate immediately".to_string(),
            related_events: Vec::new(),
        }];

        let score = SecurityReport::calculate_risk_score(&categories, &alerts);
        assert!(score > 0.0 && score <= 10.0);
    }

    #[test]
    fn test_high_priority_detection() {
        let log = LogEntry {
            timestamp: Utc::now().into(),
            process: Some("test".to_string()),
            message: Some("suspicious activity detected".to_string()),
            security_category: Some("security".to_string()),
            security_level: Some(SecurityLevel::Critical),
            subsystem: None,
            category: None,
            pid: None,
            event_type: None,
            format_string: None,
            additional_fields: HashMap::new(),
        };

        assert!(SecurityReport::is_high_priority(&log));
    }

    #[test]
    fn test_severity_determination() {
        let log = LogEntry {
            timestamp: Utc::now().into(),
            process: Some("test".to_string()),
            message: Some("Critical security breach detected".to_string()),
            security_category: Some("security".to_string()),
            security_level: Some(SecurityLevel::Critical),
            subsystem: None,
            category: None,
            pid: None,
            event_type: None,
            format_string: None,
            additional_fields: HashMap::new(),
        };

        assert_eq!(SecurityReport::determine_severity(&log), "CRITICAL");
    }

    #[test]
    fn test_alert_creation() {
        let log = LogEntry {
            timestamp: Utc::now().into(),
            process: Some("test".to_string()),
            message: Some("malware detected".to_string()),
            security_category: Some("security".to_string()),
            security_level: Some(SecurityLevel::Critical),
            subsystem: Some("security".to_string()),
            category: None,
            pid: Some(FlexibleType::Integer(123)),
            event_type: Some("security_alert".to_string()),
            format_string: None,
            additional_fields: HashMap::new(),
        };

        let alert = SecurityReport::create_security_alert(&log);
        assert_eq!(alert.severity, "CRITICAL");
        assert!(alert.recommendation.contains("scan"));
        assert_eq!(alert.context.process_info.pid, Some("123".to_string()));
    }

    #[test]
    fn test_threat_analysis() {
        let logs = vec![LogEntry {
            timestamp: Utc::now().into(),
            process: Some("test".to_string()),
            message: Some("Multiple failed login attempts detected".to_string()),
            security_category: Some("security".to_string()),
            security_level: Some(SecurityLevel::High),
            subsystem: Some("auth".to_string()),
            category: None,
            pid: Some(FlexibleType::Integer(123)),
            event_type: Some("auth_failure".to_string()),
            format_string: None,
            additional_fields: HashMap::new(),
        }];

        let analysis = SecurityReport::analyze_threats(&logs);
        assert!(!analysis.potential_threats.is_empty());
        assert!(!analysis.risk_factors.is_empty());
    }

    #[test]
    fn test_pattern_analysis() {
        let logs = vec![
            LogEntry {
                timestamp: Utc::now().into(),
                process: Some("test".to_string()),
                message: Some("Security event 1".to_string()),
                security_category: Some("security".to_string()),
                security_level: Some(SecurityLevel::Medium),
                subsystem: None,
                category: None,
                pid: None,
                event_type: Some("test_event".to_string()),
                format_string: None,
                additional_fields: HashMap::new(),
            },
            LogEntry {
                timestamp: Utc::now().into(),
                process: Some("test".to_string()),
                message: Some("Security event 2".to_string()),
                security_category: Some("security".to_string()),
                security_level: Some(SecurityLevel::Medium),
                subsystem: None,
                category: None,
                pid: None,
                event_type: Some("test_event".to_string()),
                format_string: None,
                additional_fields: HashMap::new(),
            },
        ];

        let patterns = SecurityReport::analyze_patterns(&logs);
        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].frequency, 2);
    }
}