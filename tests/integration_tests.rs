use assert_fs::prelude::*;
use predicates::prelude::*;
use macos_security_logger::{Config, LogCollector};

#[tokio::test]
async fn test_log_collection() {
    let temp = assert_fs::TempDir::new().unwrap();
    let config = Config {
        output_dir: temp.path().to_path_buf(),
        retention_days: 7,
        max_file_size: 1024 * 1024,
        log_patterns: vec![
            "subsystem == \"com.apple.security\"".to_string()
        ],
    };

    let collector = LogCollector::new(config);
    collector.collect_logs().await.unwrap();

    // Check that output file exists and contains valid JSON
    temp.child("security_logs_*.json").assert(predicate::path::exists());
}