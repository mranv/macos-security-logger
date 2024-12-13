use std::path::Path;
use serde_json::Value;
use tokio::fs;
use macos_security_logger::{Config, LogCollector};

#[tokio::test]
async fn test_log_collection() {
    let temp_dir = tempfile::tempdir().unwrap();
    let config = Config {
        output_dir: temp_dir.path().to_path_buf(),
        retention_days: 7,
        max_file_size: 1024 * 1024,
        save_raw_json: true,
        json_pretty_print: true,
        log_patterns: vec![
            "subsystem == \"com.apple.security\"".to_string(),
            "category == \"security\"".to_string(),
            "process == \"securityd\"".to_string()
        ],
    };

    let collector = LogCollector::new(config);
    collector.collect_logs().await.unwrap();

    // Wait a moment for file operations to complete
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    // Check for formatted logs
    let formatted_logs = find_json_files(temp_dir.path(), "security_logs_").await;
    assert!(!formatted_logs.is_empty(), "No formatted log files found");

    // Check for raw logs
    let raw_logs = find_json_files(temp_dir.path(), "security_logs_raw_").await;
    assert!(!raw_logs.is_empty(), "No raw log files found");

    // Validate JSON content
    for log_file in formatted_logs {
        validate_json_file(&log_file).await;
    }
}

#[tokio::test]
async fn test_log_rotation() {
    let temp_dir = tempfile::tempdir().unwrap();
    let config = Config {
        output_dir: temp_dir.path().to_path_buf(),
        retention_days: 1,
        max_file_size: 1024, // Small size to trigger rotation
        save_raw_json: true,
        json_pretty_print: true,
        log_patterns: vec![
            "subsystem == \"com.apple.security\"".to_string()
        ],
    };

    let collector = LogCollector::new(config);
    
    // Create multiple log files
    for _ in 0..3 {
        collector.collect_logs().await.unwrap();
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }

    // Check if files are rotated
    let files = find_json_files(temp_dir.path(), "security_logs_").await;
    assert!(files.len() <= 3, "Log rotation failed to limit file count");
}

#[tokio::test]
async fn test_invalid_config() {
    let temp_dir = tempfile::tempdir().unwrap();
    let config = Config {
        output_dir: temp_dir.path().join("nonexistent"),
        retention_days: 0, // Invalid retention days
        max_file_size: 0,  // Invalid file size
        save_raw_json: true,
        json_pretty_print: true,
        log_patterns: vec![],  // Empty patterns
    };

    let collector = LogCollector::new(config);
    let result = collector.collect_logs().await;
    assert!(result.is_err(), "Expected error with invalid config");
}

// Helper functions
async fn find_json_files(dir: &Path, prefix: &str) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    let mut entries = fs::read_dir(dir).await.unwrap();
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        if path.is_file() && path.file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.starts_with(prefix) && n.ends_with(".json"))
            .unwrap_or(false) {
            files.push(path);
        }
    }
    files
}

async fn validate_json_file(path: &Path) {
    let content = fs::read_to_string(path).await.unwrap();
    let json: Value = serde_json::from_str(&content).expect("Invalid JSON format");
    
    assert!(json.is_object(), "Root should be an object");
    assert!(json.get("metadata").is_some(), "Missing metadata");
    assert!(json.get("logs").is_some(), "Missing logs array");
}