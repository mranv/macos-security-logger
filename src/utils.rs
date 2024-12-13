use std::path::Path;
use tokio::fs;
use chrono::{DateTime, Local, Duration};

pub fn get_hostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .unwrap_or_else(|_| String::from("unknown"))
}

pub fn get_os_version() -> String {
    std::process::Command::new("sw_vers")
        .arg("-productVersion")
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .unwrap_or_else(|_| String::from("unknown"))
}

pub async fn cleanup_old_logs(
    dir: &Path,
    retention_days: u32,
    max_size: usize,
) -> std::io::Result<()> {
    let mut entries = fs::read_dir(dir).await?;
    let mut files = Vec::new();

    while let Some(entry) = entries.next_entry().await? {
        if entry.file_type().await?.is_file() {
            if let Ok(metadata) = entry.metadata().await {
                files.push((entry.path(), metadata));
            }
        }
    }

    // Remove old files
    let cutoff = Local::now() - Duration::days(retention_days.into());
    for (path, metadata) in &files {
        if let Ok(modified) = metadata.modified() {
            let modified: DateTime<Local> = modified.into();
            if modified < cutoff {
                fs::remove_file(path).await?;
            }
        }
    }

    // Check total size and remove oldest files if needed
    let mut total_size: usize = files.iter().map(|(_, m)| m.len() as usize).sum();
    if total_size > max_size {
        files.sort_by_key(|(_, m)| m.modified().unwrap());
        for (path, metadata) in files {
            if total_size <= max_size {
                break;
            }
            fs::remove_file(path).await?;
            total_size -= metadata.len() as usize;
        }
    }

    Ok(())
}