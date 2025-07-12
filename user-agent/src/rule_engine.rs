// user-agent/src/rule_engine.rs
// Simple rule-based threat analysis engine

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub pattern: String,
    pub risk_score: f64,
    pub threat_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleConfig {
    pub rules: Vec<Rule>,
}

impl Default for RuleConfig {
    fn default() -> Self {
        Self {
            rules: vec![
                Rule {
                    id: "sensitive_files".to_string(),
                    name: "Sensitive File Access".to_string(),
                    enabled: true,
                    pattern: "/etc/passwd|/etc/shadow".to_string(),
                    risk_score: 0.9,
                    threat_type: "Sensitive File Access".to_string(),
                },
                Rule {
                    id: "suspicious_paths".to_string(),
                    name: "Suspicious Process Paths".to_string(),
                    enabled: true,
                    pattern: "/tmp/|/var/tmp/".to_string(),
                    risk_score: 0.7,
                    threat_type: "Suspicious Process Execution".to_string(),
                },
                Rule {
                    id: "shell_execution".to_string(),
                    name: "Shell Execution".to_string(),
                    enabled: true,
                    pattern: "bash|sh|powershell".to_string(),
                    risk_score: 0.6,
                    threat_type: "Shell Execution".to_string(),
                },
            ],
        }
    }
}

#[derive(Debug, Clone)]
pub struct ThreatAnalysis {
    pub risk_score: f64,
    pub threat_type: String,
    pub matched_rule: Option<String>,
    pub description: String,
}

pub struct RuleEngine {
    rules: HashMap<String, Rule>,
}

impl RuleEngine {
    pub fn new(config: RuleConfig) -> Self {
        let mut rules = HashMap::new();
        
        for rule in config.rules {
            if rule.enabled {
                rules.insert(rule.id.clone(), rule);
            }
        }
        
        info!("Rule engine initialized with {} active rules", rules.len());
        
        Self { rules }
    }

    pub fn analyze(&self, event: &ParsedEvent) -> ThreatAnalysis {
        let mut max_risk = 0.0;
        let mut matched_rule = None;
        let mut threat_type = "Normal Activity".to_string();
        
        // Check against all rules
        for rule in self.rules.values() {
            if self.matches_pattern(&rule.pattern, &event.file_path) {
                if rule.risk_score > max_risk {
                    max_risk = rule.risk_score;
                    matched_rule = Some(rule.id.clone());
                    threat_type = rule.threat_type.clone();
                }
            }
        }
        
        ThreatAnalysis {
            risk_score: max_risk,
            threat_type,
            matched_rule,
            description: format!("Process: {} accessed: {}", event.process_name, event.file_path),
        }
    }
    
    fn matches_pattern(&self, pattern: &str, text: &str) -> bool {
        // Simple pattern matching - check if any pattern substring is contained in text
        pattern.split('|').any(|p| text.contains(p))
    }
}

#[derive(Debug, Clone)]
pub struct ParsedEvent {
    pub event_type: String,
    pub process_name: String,
    pub file_path: String,
    pub pid: u32,
    pub timestamp: u64,
} 