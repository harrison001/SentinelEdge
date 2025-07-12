// user-agent/src/config.rs
// Configuration management

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub monitoring: MonitoringConfig,
    pub response: ResponseConfig,
    pub sensitive_paths: Vec<String>,
    pub ignored_processes: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            monitoring: MonitoringConfig::default(),
            response: ResponseConfig::default(),
            sensitive_paths: vec![
                "/etc/passwd".to_string(),
                "/etc/shadow".to_string(),
                "/root/.ssh".to_string(),
            ],
            ignored_processes: vec![
                "systemd".to_string(),
                "kthreadd".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    pub monitor_network: bool,
    pub monitor_processes: bool,
    pub monitor_files: bool,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            monitor_network: true,
            monitor_processes: true,
            monitor_files: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseConfig {
    pub log_file: String,
    pub enable_quarantine: bool,
    pub enable_process_kill: bool,
    pub alert_threshold: f64,
}

impl Default for ResponseConfig {
    fn default() -> Self {
        Self {
            log_file: "./sentinel-edge.log".to_string(),
            enable_quarantine: false,
            enable_process_kill: false,
            alert_threshold: 0.7,
        }
    }
}

impl Config {
    pub fn load(path: &str) -> Result<Self> {
        // Try to load from file, fallback to default
        match std::fs::read_to_string(path) {
            Ok(content) => {
                match toml::from_str(&content) {
                    Ok(config) => Ok(config),
                    Err(_) => {
                        println!("Warning: Failed to parse config file, using defaults");
                        Ok(Self::default())
                    }
                }
            }
            Err(_) => {
                println!("Warning: Config file not found, using defaults");
                Ok(Self::default())
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct RuntimeMetrics {
    pub events_processed: u64,
    pub threats_detected: u64,
    pub average_processing_time_ms: f64,
    pub uptime_seconds: u64,
}

impl Default for RuntimeMetrics {
    fn default() -> Self {
        Self {
            events_processed: 0,
            threats_detected: 0,
            average_processing_time_ms: 0.0,
            uptime_seconds: 0,
        }
    }
} 