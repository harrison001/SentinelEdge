// user-agent/src/threat_classifier.rs
// Rule-based threat classification engine

use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAnalysisConfig {
    pub enable_file_analysis: bool,
    pub enable_process_analysis: bool,
    pub confidence_threshold: f64,
}

impl Default for ThreatAnalysisConfig {
    fn default() -> Self {
        Self {
            enable_file_analysis: true,
            enable_process_analysis: true,
            confidence_threshold: 0.5,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAnalysis {
    pub risk_score: f64,
    pub confidence: f64,
    pub threat_type: String,
    pub severity: String,
    pub description: String,
    pub recommended_actions: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ParsedEvent {
    pub event_type: String,
    pub process_name: String,
    pub file_path: String,
    pub pid: u32,
    pub timestamp: u64,
}

pub struct ThreatClassifier {
    config: ThreatAnalysisConfig,
}

impl ThreatClassifier {
    pub fn new(config: &ThreatAnalysisConfig) -> Result<Self> {
        Ok(Self {
            config: config.clone(),
        })
    }

    pub fn classify_threat(&self, event: &ParsedEvent) -> Result<ThreatAnalysis> {
        let file_path = &event.file_path;
        
        // Check for sensitive system files
        if file_path.contains("/etc/passwd") || file_path.contains("/etc/shadow") {
            return Ok(ThreatAnalysis {
                risk_score: 0.9,
                confidence: 0.95,
                threat_type: "Sensitive File Access".to_string(),
                severity: "high".to_string(),
                description: format!("Access to system sensitive file: {}", file_path),
                recommended_actions: vec!["alert".to_string(), "block".to_string()],
            });
        }
        
        // Check for suspicious file paths
        if file_path.contains("/tmp/") || file_path.contains("sh") || file_path.contains("bash") {
            return Ok(ThreatAnalysis {
                risk_score: 0.7,
                confidence: 0.9,
                threat_type: "Suspicious Process Execution".to_string(),
                severity: "medium".to_string(),
                description: format!("Temp directory or shell execution: {}", file_path),
                recommended_actions: vec!["monitor".to_string(), "alert".to_string()],
            });
        }
        
        // Regular system binaries
        if file_path.contains("/bin/") || file_path.contains("/usr/bin/") {
            return Ok(ThreatAnalysis {
                risk_score: 0.2,
                confidence: 0.8,
                threat_type: "Normal Process".to_string(),
                severity: "low".to_string(),
                description: format!("Regular system process: {}", file_path),
                recommended_actions: vec!["log".to_string()],
            });
        }
        
        // Default case
        Ok(ThreatAnalysis {
            risk_score: 0.1,
            confidence: 0.5,
            threat_type: "Unknown Process".to_string(),
            severity: "info".to_string(),
            description: "Process execution with incomplete information".to_string(),
            recommended_actions: vec!["log".to_string()],
        })
    }
} 