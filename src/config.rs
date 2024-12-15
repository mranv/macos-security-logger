use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub output_dir: PathBuf,
    pub retention_days: u32,
    pub max_file_size: usize,
    #[serde(default = "default_save_raw_json")]
    pub save_raw_json: bool,
    #[serde(default = "default_json_pretty_print")]
    pub json_pretty_print: bool,
    pub log_patterns: HashMap<String, Vec<String>>,
    #[serde(skip)]
    pub time_range: Option<String>,
    #[serde(skip)]
    pub start_time: Option<String>,
    #[serde(skip)]
    pub end_time: Option<String>,
}

fn default_save_raw_json() -> bool {
    true
}

fn default_json_pretty_print() -> bool {
    true
}

#[derive(Debug, Serialize)]
pub struct SecurityStats {
    pub category: String,
    pub events_count: usize,
    pub last_event: Option<String>,
}

impl Config {
    pub fn load(path: Option<&str>) -> anyhow::Result<Self> {
        let mut builder = config::Config::builder();
        
        // Load default config
        builder = builder.add_source(config::File::with_name("config/default"));

        // Load environment-specific config if exists
        if let Ok(env) = std::env::var("RUN_ENV") {
            builder = builder.add_source(
                config::File::with_name(&format!("config/{}", env))
                    .required(false)
            );
        }

        // Load user-specified config if provided
        if let Some(path) = path {
            builder = builder.add_source(config::File::with_name(path));
        }

        // Add environment variables prefixed with APP_
        builder = builder.add_source(
            config::Environment::with_prefix("APP")
                .separator("_")
        );

        let config = builder.build()?;
        config.try_deserialize().map_err(Into::into)
    }

    pub fn get_time_args(&self) -> Vec<String> {
        let mut args = Vec::new();

        if let Some(range) = &self.time_range {
            args.push("--last".to_string());
            args.push(range.clone());
        } else {
            if let Some(start) = &self.start_time {
                args.push("--start".to_string());
                args.push(start.clone());
            }
            if let Some(end) = &self.end_time {
                args.push("--end".to_string());
                args.push(end.clone());
            }
        }

        if args.is_empty() {
            // Default to last 1 hour if no time range specified
            args.push("--last".to_string());
            args.push("1h".to_string());
        }

        args
    }

    pub fn filter_categories(&mut self, categories: &[String]) {
        let all_patterns = self.log_patterns.clone();
        self.log_patterns.clear();

        for category in categories {
            if let Some(patterns) = all_patterns.get(category) {
                self.log_patterns.insert(category.clone(), patterns.clone());
            }
        }
    }

    pub fn get_all_patterns(&self) -> Vec<String> {
        self.log_patterns.values()
            .flat_map(|patterns| patterns.clone())
            .collect()
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.retention_days == 0 {
            return Err("retention_days must be greater than 0".to_string());
        }
        if self.max_file_size == 0 {
            return Err("max_file_size must be greater than 0".to_string());
        }
        if self.log_patterns.is_empty() {
            return Err("log_patterns cannot be empty".to_string());
        }
        Ok(())
    }
}