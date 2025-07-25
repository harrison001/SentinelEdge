// kernel-agent/src/config_validation.rs
// Configuration validation and adaptive optimization

use crate::error::*;
use crate::EbpfConfig;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, info, warn, error};

/// Configuration validator with comprehensive checks
pub struct ConfigValidator {
    system_constraints: SystemConstraints,
    validation_rules: Vec<ValidationRule>,
}

/// System resource constraints detected at runtime
#[derive(Debug, Clone)]
pub struct SystemConstraints {
    pub total_memory_mb: u64,
    pub available_memory_mb: u64,
    pub cpu_cores: u64,
    pub kernel_version: String,
    pub has_bpf_support: bool,
    pub max_locked_memory_kb: Option<u64>,
    pub page_size: u64,
}

/// Configuration validation rule
#[derive(Debug, Clone)]
pub struct ValidationRule {
    pub name: String,
    pub description: String,
    pub validator: fn(&EbpfConfig, &SystemConstraints) -> ValidationResult,
    pub severity: ValidationSeverity,
}

/// Result of configuration validation
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub is_valid: bool,
    pub message: String,
    pub suggested_value: Option<ConfigValue>,
}

/// Configuration value types
#[derive(Debug, Clone)]
pub enum ConfigValue {
    USize(usize),
    U64(u64),
    Bool(bool),
    Duration(Duration),
}

/// Validation severity levels
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ValidationSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

/// Comprehensive validation report
#[derive(Debug, Clone)]
pub struct ValidationReport {
    pub is_valid: bool,
    pub issues: Vec<ValidationIssue>,
    pub suggestions: Vec<ConfigSuggestion>,
    pub optimized_config: Option<EbpfConfig>,
}

/// Individual validation issue
#[derive(Debug, Clone)]
pub struct ValidationIssue {
    pub rule_name: String,
    pub severity: ValidationSeverity,
    pub message: String,
    pub field: String,
    pub current_value: String,
}

/// Configuration optimization suggestion
#[derive(Debug, Clone)]
pub struct ConfigSuggestion {
    pub field: String,
    pub current_value: String,
    pub suggested_value: String,
    pub reason: String,
    pub impact: OptimizationImpact,
}

/// Impact of configuration optimization
#[derive(Debug, Clone)]
pub enum OptimizationImpact {
    Performance { improvement_percent: f64 },
    Memory { reduction_mb: u64 },
    Reliability { risk_reduction: String },
    Compatibility { issue_resolution: String },
}

impl ConfigValidator {
    /// Create a new configuration validator
    pub async fn new() -> Result<Self> {
        let system_constraints = Self::detect_system_constraints().await?;
        let validation_rules = Self::create_validation_rules();
        
        info!("Initialized config validator with {} rules", validation_rules.len());
        debug!("System constraints: {:?}", system_constraints);
        
        Ok(Self {
            system_constraints,
            validation_rules,
        })
    }

    /// Validate configuration comprehensively
    pub async fn validate(&self, config: &EbpfConfig) -> ValidationReport {
        let mut issues = Vec::new();
        let mut suggestions = Vec::new();
        let mut has_critical_errors = false;

        info!("Starting comprehensive configuration validation");

        for rule in &self.validation_rules {
            let result = (rule.validator)(config, &self.system_constraints);
            
            if !result.is_valid {
                let issue = ValidationIssue {
                    rule_name: rule.name.clone(),
                    severity: rule.severity.clone(),
                    message: result.message.clone(),
                    field: "various".to_string(), // Could be more specific
                    current_value: "see message".to_string(),
                };

                if rule.severity >= ValidationSeverity::Critical {
                    has_critical_errors = true;
                }

                issues.push(issue);
            }

            if let Some(suggested_value) = result.suggested_value {
                let suggestion = self.create_suggestion_from_result(&rule.name, suggested_value, &result.message);
                suggestions.push(suggestion);
            }
        }

        // Generate optimized configuration if possible
        let optimized_config = if !has_critical_errors {
            Some(self.generate_optimized_config(config, &suggestions).await)
        } else {
            None
        };

        let is_valid = issues.iter().all(|i| i.severity < ValidationSeverity::Error);

        ValidationReport {
            is_valid,
            issues,
            suggestions,
            optimized_config,
        }
    }

    /// Auto-optimize configuration based on system characteristics
    pub async fn auto_optimize(&self, config: &EbpfConfig) -> Result<EbpfConfig> {
        info!("Starting automatic configuration optimization");

        let mut optimized = config.clone();

        // Memory-based optimizations
        optimized = self.optimize_for_memory(&optimized).await?;
        
        // CPU-based optimizations
        optimized = self.optimize_for_cpu(&optimized).await?;
        
        // Performance optimizations
        optimized = self.optimize_for_performance(&optimized).await?;

        // Validate the optimized configuration
        let validation_report = self.validate(&optimized).await;
        if !validation_report.is_valid {
            warn!("Auto-optimized configuration failed validation, using conservative settings");
            optimized = self.create_conservative_config().await;
        }

        info!("Configuration optimization completed");
        Ok(optimized)
    }

    /// Detect system constraints at runtime
    async fn detect_system_constraints() -> Result<SystemConstraints> {
        let total_memory_mb = Self::get_total_memory().await?;
        let available_memory_mb = Self::get_available_memory().await?;
        let cpu_cores = Self::get_cpu_cores().await?;
        let kernel_version = Self::get_kernel_version().await?;
        let has_bpf_support = Self::check_bpf_support().await;
        let max_locked_memory_kb = Self::get_max_locked_memory().await;
        let page_size = Self::get_page_size().await?;

        Ok(SystemConstraints {
            total_memory_mb,
            available_memory_mb,
            cpu_cores,
            kernel_version,
            has_bpf_support,
            max_locked_memory_kb,
            page_size,
        })
    }

    /// Create comprehensive validation rules
    fn create_validation_rules() -> Vec<ValidationRule> {
        vec![
            ValidationRule {
                name: "ring_buffer_size_bounds".to_string(),
                description: "Ring buffer size must be within reasonable bounds".to_string(),
                validator: |config, constraints| {
                    let min_size = 4096; // 4KB minimum
                    let max_size = (constraints.available_memory_mb * 1024 * 1024 / 4) as usize; // 25% of available memory
                    
                    if config.ring_buffer_size < min_size {
                        ValidationResult {
                            is_valid: false,
                            message: format!("Ring buffer size {} is too small (minimum {})", config.ring_buffer_size, min_size),
                            suggested_value: Some(ConfigValue::USize(min_size)),
                        }
                    } else if config.ring_buffer_size > max_size {
                        ValidationResult {
                            is_valid: false,
                            message: format!("Ring buffer size {} exceeds available memory limit (maximum {})", config.ring_buffer_size, max_size),
                            suggested_value: Some(ConfigValue::USize(max_size)),
                        }
                    } else {
                        ValidationResult {
                            is_valid: true,
                            message: "Ring buffer size is appropriate".to_string(),
                            suggested_value: None,
                        }
                    }
                },
                severity: ValidationSeverity::Error,
            },
            ValidationRule {
                name: "power_of_two_buffer".to_string(),
                description: "Ring buffer size should be a power of two for optimal performance".to_string(),
                validator: |config, _| {
                    let is_power_of_two = config.ring_buffer_size > 0 && (config.ring_buffer_size & (config.ring_buffer_size - 1)) == 0;
                    
                    if !is_power_of_two {
                        let next_power = config.ring_buffer_size.next_power_of_two();
                        ValidationResult {
                            is_valid: false,
                            message: format!("Ring buffer size {} is not a power of two, which may impact performance", config.ring_buffer_size),
                            suggested_value: Some(ConfigValue::USize(next_power)),
                        }
                    } else {
                        ValidationResult {
                            is_valid: true,
                            message: "Ring buffer size is a power of two".to_string(),
                            suggested_value: None,
                        }
                    }
                },
                severity: ValidationSeverity::Warning,
            },
            ValidationRule {
                name: "batch_size_efficiency".to_string(),
                description: "Event batch size should be optimized for throughput".to_string(),
                validator: |config, constraints| {
                    let optimal_batch_size = (constraints.cpu_cores * 16) as usize; // 16 events per core
                    let min_batch = 8;
                    let max_batch = 1000;
                    
                    if config.event_batch_size < min_batch {
                        ValidationResult {
                            is_valid: false,
                            message: format!("Batch size {} is too small, may cause overhead", config.event_batch_size),
                            suggested_value: Some(ConfigValue::USize(optimal_batch_size.max(min_batch))),
                        }
                    } else if config.event_batch_size > max_batch {
                        ValidationResult {
                            is_valid: false,
                            message: format!("Batch size {} is too large, may cause latency", config.event_batch_size),
                            suggested_value: Some(ConfigValue::USize(optimal_batch_size.min(max_batch))),
                        }
                    } else {
                        ValidationResult {
                            is_valid: true,
                            message: "Batch size is within acceptable range".to_string(),
                            suggested_value: if config.event_batch_size != optimal_batch_size {
                                Some(ConfigValue::USize(optimal_batch_size))
                            } else {
                                None
                            },
                        }
                    }
                },
                severity: ValidationSeverity::Warning,
            },
            ValidationRule {
                name: "rate_limit_sanity".to_string(),
                description: "Rate limit should be reasonable for system capacity".to_string(),
                validator: |config, constraints| {
                    let max_reasonable_rate = (constraints.cpu_cores * 5000) as usize; // 5000 events per core per second
                    
                    if config.max_events_per_sec == 0 {
                        ValidationResult {
                            is_valid: false,
                            message: "Rate limit cannot be zero".to_string(),
                            suggested_value: Some(ConfigValue::USize(1000)),
                        }
                    } else if config.max_events_per_sec > max_reasonable_rate {
                        ValidationResult {
                            is_valid: false,
                            message: format!("Rate limit {} may overwhelm system (max recommended: {})", config.max_events_per_sec, max_reasonable_rate),
                            suggested_value: Some(ConfigValue::USize(max_reasonable_rate)),
                        }
                    } else {
                        ValidationResult {
                            is_valid: true,
                            message: "Rate limit is reasonable".to_string(),
                            suggested_value: None,
                        }
                    }
                },
                severity: ValidationSeverity::Warning,
            },
            ValidationRule {
                name: "timeout_consistency".to_string(),
                description: "Timeout values should be consistent and reasonable".to_string(),
                validator: |config, _| {
                    if let (Some(ring_timeout), Some(batch_timeout)) = (config.ring_buffer_poll_timeout_us, config.batch_timeout_us) {
                        if batch_timeout < ring_timeout {
                            ValidationResult {
                                is_valid: false,
                                message: "Batch timeout should not be less than ring buffer poll timeout".to_string(),
                                suggested_value: Some(ConfigValue::U64(ring_timeout * 2)),
                            }
                        } else {
                            ValidationResult {
                                is_valid: true,
                                message: "Timeout values are consistent".to_string(),
                                suggested_value: None,
                            }
                        }
                    } else {
                        ValidationResult {
                            is_valid: true,
                            message: "Timeout configuration is valid".to_string(),
                            suggested_value: None,
                        }
                    }
                },
                severity: ValidationSeverity::Info,
            },
        ]
    }

    /// Optimize configuration for memory usage
    async fn optimize_for_memory(&self, config: &EbpfConfig) -> Result<EbpfConfig> {
        let mut optimized = config.clone();
        
        // Adjust ring buffer size based on available memory
        let available_mb = self.system_constraints.available_memory_mb;
        if available_mb < 512 { // Low memory system
            optimized.ring_buffer_size = (64 * 1024).min(optimized.ring_buffer_size); // 64KB max
            optimized.event_batch_size = 32.min(optimized.event_batch_size);
        } else if available_mb < 2048 { // Medium memory system
            optimized.ring_buffer_size = (256 * 1024).min(optimized.ring_buffer_size); // 256KB max
            optimized.event_batch_size = 64.min(optimized.event_batch_size);
        }
        // High memory systems keep original values

        debug!("Memory optimization: ring_buffer_size={}, event_batch_size={}", 
            optimized.ring_buffer_size, optimized.event_batch_size);
        
        Ok(optimized)
    }

    /// Optimize configuration for CPU usage
    async fn optimize_for_cpu(&self, config: &EbpfConfig) -> Result<EbpfConfig> {
        let mut optimized = config.clone();
        
        // Adjust batch size and timeouts based on CPU cores
        let cpu_cores = self.system_constraints.cpu_cores;
        
        optimized.event_batch_size = ((cpu_cores * 16) as usize).min(512); // 16 events per core, max 512
        optimized.max_events_per_sec = ((cpu_cores * 3000) as usize).max(1000); // 3000 events per core per second, min 1000
        
        // Adjust polling timeout for better CPU utilization
        if cpu_cores <= 2 {
            optimized.ring_buffer_poll_timeout_us = Some(200); // Higher latency, lower CPU on low-core systems
        } else if cpu_cores >= 8 {
            optimized.ring_buffer_poll_timeout_us = Some(50);  // Lower latency on high-core systems
        }

        debug!("CPU optimization: cores={}, batch_size={}, max_events_per_sec={}", 
            cpu_cores, optimized.event_batch_size, optimized.max_events_per_sec);
        
        Ok(optimized)
    }

    /// Optimize configuration for performance
    async fn optimize_for_performance(&self, config: &EbpfConfig) -> Result<EbpfConfig> {
        let mut optimized = config.clone();
        
        // Enable all performance features
        optimized.enable_backpressure = true;
        optimized.auto_recovery = true;
        
        // Optimize batch timing
        if let Some(batch_size) = optimized.batch_size {
            // Ensure batch timeout is proportional to batch size
            let optimal_timeout = (batch_size * 50) as u64; // 50 microseconds per event
            optimized.batch_timeout_us = Some(optimal_timeout.max(500).min(5000)); // Between 0.5ms and 5ms
        }

        // Ensure ring buffer size is a power of two
        if optimized.ring_buffer_size > 0 && (optimized.ring_buffer_size & (optimized.ring_buffer_size - 1)) != 0 {
            optimized.ring_buffer_size = optimized.ring_buffer_size.next_power_of_two();
        }

        debug!("Performance optimization completed: ring_buffer_size={}, batch_timeout_us={:?}", 
            optimized.ring_buffer_size, optimized.batch_timeout_us);
        
        Ok(optimized)
    }

    /// Create a conservative configuration for problematic systems
    async fn create_conservative_config(&self) -> EbpfConfig {
        EbpfConfig {
            ring_buffer_size: 64 * 1024,  // 64KB - small and safe
            event_batch_size: 16,         // Small batches
            poll_timeout_ms: 100,         // Conservative polling
            max_events_per_sec: 500,      // Low rate limit
            enable_backpressure: true,    // Always enable safety features
            auto_recovery: true,
            metrics_interval_sec: 60,
            ring_buffer_poll_timeout_us: Some(200), // Higher latency for stability
            batch_size: Some(16),
            batch_timeout_us: Some(2000), // 2ms timeout
        }
    }

    /// Generate optimized configuration from suggestions
    async fn generate_optimized_config(&self, base_config: &EbpfConfig, suggestions: &[ConfigSuggestion]) -> EbpfConfig {
        let mut optimized = base_config.clone();

        for suggestion in suggestions {
            match suggestion.field.as_str() {
                "ring_buffer_size" => {
                    if let Ok(value) = suggestion.suggested_value.parse::<usize>() {
                        optimized.ring_buffer_size = value;
                    }
                }
                "event_batch_size" => {
                    if let Ok(value) = suggestion.suggested_value.parse::<usize>() {
                        optimized.event_batch_size = value;
                    }
                }
                "max_events_per_sec" => {
                    if let Ok(value) = suggestion.suggested_value.parse::<usize>() {
                        optimized.max_events_per_sec = value;
                    }
                }
                _ => {} // Unknown field, skip
            }
        }

        optimized
    }

    /// Create suggestion from validation result
    fn create_suggestion_from_result(&self, rule_name: &str, suggested_value: ConfigValue, reason: &str) -> ConfigSuggestion {
        let (field, current_val, suggested_val, impact) = match suggested_value {
            ConfigValue::USize(val) => {
                let field = if rule_name.contains("buffer") {
                    "ring_buffer_size"
                } else if rule_name.contains("batch") {
                    "event_batch_size"
                } else {
                    "unknown"
                };
                (field.to_string(), "current".to_string(), val.to_string(), 
                 OptimizationImpact::Performance { improvement_percent: 15.0 })
            }
            ConfigValue::U64(val) => {
                ("timeout".to_string(), "current".to_string(), val.to_string(),
                 OptimizationImpact::Performance { improvement_percent: 10.0 })
            }
            ConfigValue::Bool(val) => {
                ("feature".to_string(), "current".to_string(), val.to_string(),
                 OptimizationImpact::Reliability { risk_reduction: "Improved stability".to_string() })
            }
            ConfigValue::Duration(val) => {
                ("timeout".to_string(), "current".to_string(), format!("{}ms", val.as_millis()),
                 OptimizationImpact::Performance { improvement_percent: 5.0 })
            }
        };

        ConfigSuggestion {
            field,
            current_value: current_val,
            suggested_value: suggested_val,
            reason: reason.to_string(),
            impact,
        }
    }

    // System information gathering methods
    async fn get_total_memory() -> Result<u64> {
        #[cfg(target_os = "linux")]
        {
            use std::fs;
            let contents = fs::read_to_string("/proc/meminfo")
                .map_err(|e| SentinelError::Io { operation: "read /proc/meminfo".to_string(), source: e })?;
            
            for line in contents.lines() {
                if line.starts_with("MemTotal:") {
                    if let Some(kb_str) = line.split_whitespace().nth(1) {
                        let kb = kb_str.parse::<u64>().unwrap_or(0);
                        return Ok(kb / 1024); // Convert to MB
                    }
                }
            }
            Ok(1024) // Default fallback
        }
        
        #[cfg(not(target_os = "linux"))]
        Ok(4096) // Default 4GB for non-Linux systems
    }

    async fn get_available_memory() -> Result<u64> {
        #[cfg(target_os = "linux")]
        {
            use std::fs;
            let contents = fs::read_to_string("/proc/meminfo")
                .map_err(|e| SentinelError::Io { operation: "read /proc/meminfo".to_string(), source: e })?;
            
            for line in contents.lines() {
                if line.starts_with("MemAvailable:") {
                    if let Some(kb_str) = line.split_whitespace().nth(1) {
                        let kb = kb_str.parse::<u64>().unwrap_or(0);
                        return Ok(kb / 1024); // Convert to MB
                    }
                }
            }
            // Fallback to MemFree if MemAvailable not found
            for line in contents.lines() {
                if line.starts_with("MemFree:") {
                    if let Some(kb_str) = line.split_whitespace().nth(1) {
                        let kb = kb_str.parse::<u64>().unwrap_or(0);
                        return Ok(kb / 1024); // Convert to MB
                    }
                }
            }
            Ok(512) // Conservative fallback
        }
        
        #[cfg(not(target_os = "linux"))]
        Ok(2048) // Default 2GB available for non-Linux systems
    }

    async fn get_cpu_cores() -> Result<u64> {
        Ok(num_cpus::get() as u64)
    }

    async fn get_kernel_version() -> Result<String> {
        #[cfg(target_os = "linux")]
        {
            use std::fs;
            let version = fs::read_to_string("/proc/version")
                .map_err(|e| SentinelError::Io { operation: "read /proc/version".to_string(), source: e })?;
            Ok(version.lines().next().unwrap_or("unknown").to_string())
        }
        
        #[cfg(not(target_os = "linux"))]
        Ok("non-linux".to_string())
    }

    async fn check_bpf_support() -> bool {
        #[cfg(target_os = "linux")]
        {
            use std::fs;
            // Check for BPF support by looking for /sys/fs/bpf
            fs::metadata("/sys/fs/bpf").is_ok()
        }
        
        #[cfg(not(target_os = "linux"))]
        false
    }

    async fn get_max_locked_memory() -> Option<u64> {
        #[cfg(target_os = "linux")]
        {
            use std::fs;
            if let Ok(contents) = fs::read_to_string("/proc/self/limits") {
                for line in contents.lines() {
                    if line.contains("Max locked memory") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 4 {
                            if let Ok(value) = parts[3].parse::<u64>() {
                                return Some(value);
                            }
                        }
                    }
                }
            }
            None
        }
        
        #[cfg(not(target_os = "linux"))]
        None
    }

    async fn get_page_size() -> Result<u64> {
        #[cfg(unix)]
        {
            use libc;
            let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
            if page_size > 0 {
                Ok(page_size as u64)
            } else {
                Ok(4096) // Default page size
            }
        }
        
        #[cfg(not(unix))]
        Ok(4096) // Default page size for non-Unix systems
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_config_validation() {
        let validator = ConfigValidator::new().await.unwrap();
        
        let config = EbpfConfig {
            ring_buffer_size: 0, // Invalid size
            event_batch_size: 100,
            poll_timeout_ms: 100,
            max_events_per_sec: 1000,
            enable_backpressure: true,
            auto_recovery: true,
            metrics_interval_sec: 60,
            ring_buffer_poll_timeout_us: Some(100),
            batch_size: Some(64),
            batch_timeout_us: Some(1000),
        };

        let report = validator.validate(&config).await;
        assert!(!report.is_valid);
        assert!(!report.issues.is_empty());
    }

    #[tokio::test]
    async fn test_auto_optimization() {
        let validator = ConfigValidator::new().await.unwrap();
        
        let config = EbpfConfig::default();
        let optimized = validator.auto_optimize(&config).await.unwrap();
        
        // Should be valid after optimization
        let report = validator.validate(&optimized).await;
        assert!(report.is_valid || report.issues.iter().all(|i| i.severity < ValidationSeverity::Error));
    }

    #[test]
    fn test_power_of_two_validation() {
        let constraints = SystemConstraints {
            total_memory_mb: 4096,
            available_memory_mb: 2048,
            cpu_cores: 4,
            kernel_version: "5.4.0".to_string(),
            has_bpf_support: true,
            max_locked_memory_kb: Some(65536),
            page_size: 4096,
        };

        let rules = ConfigValidator::create_validation_rules();
        let power_of_two_rule = rules.iter().find(|r| r.name == "power_of_two_buffer").unwrap();

        let config_not_power_of_two = EbpfConfig {
            ring_buffer_size: 100000, // Not a power of two
            ..EbpfConfig::default()
        };

        let result = (power_of_two_rule.validator)(&config_not_power_of_two, &constraints);
        assert!(!result.is_valid);
        assert!(result.suggested_value.is_some());
    }
}