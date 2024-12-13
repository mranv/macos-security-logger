use serde::Deserialize;
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
    pub log_patterns: Vec<String>,
}

fn default_save_raw_json() -> bool {
    true
}

fn default_json_pretty_print() -> bool {
    true
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
}