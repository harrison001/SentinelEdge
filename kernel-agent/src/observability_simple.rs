// kernel-agent/src/observability_simple.rs
// Simplified observability and monitoring for SentinelEdge

use crate::error::*;
use crate::EbpfMetrics;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, info, warn, error, instrument};

/// Simplified metrics collector for SentinelEdge
#[derive(Debug, Clone, Default)]
pub struct SentinelMetrics {
    // Event processing metrics
    pub events_processed_total: u64,
    pub events_dropped_total: u64,
    pub events_by_type: HashMap<String, u64>,
    
    // Performance metrics
    pub avg_processing_time_ns: u64,
    pub ring_buffer_utilization: f64,
    pub memory_usage_bytes: u64,
    
    // Error metrics
    pub errors_by_type: HashMap<String, u64>,
    pub error_recovery_attempts: u64,
    
    // System health metrics
    pub system_uptime_seconds: u64,
    pub cpu_usage_percent: f64,
    pub thread_count: u64,
    
    // Metrics metadata
    pub start_time_ms: u64,
    pub last_update_ms: u64,
}

impl SentinelMetrics {
    /// Create a new metrics collector
    pub fn new() -> Self {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
            
        Self {
            events_processed_total: 0,
            events_dropped_total: 0,
            events_by_type: HashMap::new(),
            
            avg_processing_time_ns: 0,
            ring_buffer_utilization: 0.0,
            memory_usage_bytes: 0,
            
            errors_by_type: HashMap::new(),
            error_recovery_attempts: 0,
            
            system_uptime_seconds: 0,
            cpu_usage_percent: 0.0,
            thread_count: 1,
            
            start_time_ms: now_ms,
            last_update_ms: now_ms,
        }
    }

    /// Record an event being processed
    pub fn record_event_processed(&mut self, event_type: &str, processing_duration: Duration) {
        self.events_processed_total += 1;
        
        // Update average processing time
        let duration_ns = processing_duration.as_nanos() as u64;
        if self.avg_processing_time_ns == 0 {
            self.avg_processing_time_ns = duration_ns;
        } else {
            // Exponential moving average
            self.avg_processing_time_ns = (self.avg_processing_time_ns * 9 + duration_ns) / 10;
        }
        
        // Track events by type
        *self.events_by_type.entry(event_type.to_string()).or_insert(0) += 1;
        
        self.update_timestamp();
        debug!("Recorded event: type={}, duration={:?}", event_type, processing_duration);
    }

    /// Record an event being dropped
    pub fn record_event_dropped(&mut self, reason: &str) {
        self.events_dropped_total += 1;
        *self.errors_by_type.entry(reason.to_string()).or_insert(0) += 1;
        self.update_timestamp();
        warn!("Event dropped: reason={}", reason);
    }

    /// Record an error occurrence
    pub fn record_error(&mut self, error_type: &str) {
        *self.errors_by_type.entry(error_type.to_string()).or_insert(0) += 1;
        self.update_timestamp();
        error!("Error recorded: type={}", error_type);
    }

    /// Update ring buffer utilization
    pub fn update_ring_buffer_utilization(&mut self, utilization_percent: f64) {
        self.ring_buffer_utilization = utilization_percent;
        self.update_timestamp();
    }

    /// Update memory usage
    pub fn update_memory_usage(&mut self, bytes: u64) {
        self.memory_usage_bytes = bytes;
        self.update_timestamp();
    }

    /// Update CPU usage
    pub fn update_cpu_usage(&mut self, percent: f64) {
        self.cpu_usage_percent = percent;
        self.update_timestamp();
    }

    /// Get a summary of all metrics
    pub fn get_summary(&self) -> MetricsSummary {
        let total_events = self.events_processed_total + self.events_dropped_total;
        let drop_rate = if total_events > 0 {
            (self.events_dropped_total as f64 / total_events as f64) * 100.0
        } else {
            0.0
        };

        let uptime_seconds = if self.start_time_ms > 0 {
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            (now_ms - self.start_time_ms) / 1000
        } else {
            0
        };

        MetricsSummary {
            events_processed: self.events_processed_total,
            events_dropped: self.events_dropped_total,
            drop_rate_percent: drop_rate,
            avg_processing_time_ns: self.avg_processing_time_ns,
            ring_buffer_utilization: self.ring_buffer_utilization,
            memory_usage_mb: (self.memory_usage_bytes as f64) / 1024.0 / 1024.0,
            cpu_usage_percent: self.cpu_usage_percent,
            uptime_seconds,
            error_count: self.errors_by_type.values().sum(),
        }
    }

    /// Reset all metrics
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    fn update_timestamp(&mut self) {
        self.last_update_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
    }
}

/// Summary of metrics for easy reporting
#[derive(Debug, Clone)]
pub struct MetricsSummary {
    pub events_processed: u64,
    pub events_dropped: u64,
    pub drop_rate_percent: f64,
    pub avg_processing_time_ns: u64,
    pub ring_buffer_utilization: f64,
    pub memory_usage_mb: f64,
    pub cpu_usage_percent: f64,
    pub uptime_seconds: u64,
    pub error_count: u64,
}

/// Health status enumeration
#[derive(Debug, Clone, PartialEq)]
pub enum HealthStatus {
    Healthy,
    Warning,
    Critical,
    Unknown,
}

/// Health checker for SentinelEdge components
pub struct HealthChecker {
    checks: Vec<Box<dyn Fn(&SentinelMetrics) -> HealthStatus + Send + Sync>>,
    thresholds: HealthThresholds,
}

#[derive(Debug)]
pub struct HealthThresholds {
    pub max_drop_rate_percent: f64,
    pub max_avg_latency_ms: f64,
    pub max_memory_usage_mb: f64,
    pub max_cpu_usage_percent: f64,
    pub max_error_rate_per_minute: f64,
}

impl Default for HealthThresholds {
    fn default() -> Self {
        Self {
            max_drop_rate_percent: 5.0,
            max_avg_latency_ms: 10.0,
            max_memory_usage_mb: 1024.0,
            max_cpu_usage_percent: 80.0,
            max_error_rate_per_minute: 10.0,
        }
    }
}

impl HealthChecker {
    /// Create a new health checker with default thresholds
    pub fn new() -> Self {
        Self::with_thresholds(HealthThresholds::default())
    }

    /// Create a health checker with custom thresholds
    pub fn with_thresholds(thresholds: HealthThresholds) -> Self {
        let mut checker = Self {
            checks: Vec::new(),
            thresholds,
        };

        // Add default health checks
        checker.add_default_checks();
        checker
    }

    /// Add default health checks
    fn add_default_checks(&mut self) {
        // Drop rate check
        let max_drop_rate = self.thresholds.max_drop_rate_percent;
        self.checks.push(Box::new(move |metrics: &SentinelMetrics| {
            let summary = metrics.get_summary();
            if summary.drop_rate_percent > max_drop_rate {
                HealthStatus::Critical
            } else if summary.drop_rate_percent > max_drop_rate / 2.0 {
                HealthStatus::Warning
            } else {
                HealthStatus::Healthy
            }
        }));

        // Latency check
        let max_latency_ns = (self.thresholds.max_avg_latency_ms * 1_000_000.0) as u64;
        self.checks.push(Box::new(move |metrics: &SentinelMetrics| {
            if metrics.avg_processing_time_ns > max_latency_ns {
                HealthStatus::Critical
            } else if metrics.avg_processing_time_ns > max_latency_ns / 2 {
                HealthStatus::Warning
            } else {
                HealthStatus::Healthy
            }
        }));

        // Memory check
        let max_memory_bytes = (self.thresholds.max_memory_usage_mb * 1024.0 * 1024.0) as u64;
        self.checks.push(Box::new(move |metrics: &SentinelMetrics| {
            if metrics.memory_usage_bytes > max_memory_bytes {
                HealthStatus::Critical
            } else if metrics.memory_usage_bytes > max_memory_bytes / 2 {
                HealthStatus::Warning
            } else {
                HealthStatus::Healthy
            }
        }));

        // CPU check
        let max_cpu = self.thresholds.max_cpu_usage_percent;
        self.checks.push(Box::new(move |metrics: &SentinelMetrics| {
            if metrics.cpu_usage_percent > max_cpu {
                HealthStatus::Critical
            } else if metrics.cpu_usage_percent > max_cpu * 0.75 {
                HealthStatus::Warning
            } else {
                HealthStatus::Healthy
            }
        }));
    }

    /// Check overall system health
    pub fn check_health(&self, metrics: &SentinelMetrics) -> HealthStatus {
        let mut worst_status = HealthStatus::Healthy;

        for check in &self.checks {
            let status = check(metrics);
            worst_status = match (&worst_status, &status) {
                (_, HealthStatus::Critical) => HealthStatus::Critical,
                (HealthStatus::Critical, _) => HealthStatus::Critical,
                (_, HealthStatus::Warning) => HealthStatus::Warning,
                (HealthStatus::Warning, _) => HealthStatus::Warning,
                (_, HealthStatus::Unknown) => HealthStatus::Unknown,
                (HealthStatus::Unknown, _) => HealthStatus::Unknown,
                _ => HealthStatus::Healthy,
            };

            // Short-circuit on critical status
            if matches!(worst_status, HealthStatus::Critical) {
                break;
            }
        }

        worst_status
    }

    /// Get detailed health report
    pub fn get_health_report(&self, metrics: &SentinelMetrics) -> HealthReport {
        let overall_status = self.check_health(metrics);
        let summary = metrics.get_summary();

        let mut issues = Vec::new();
        let mut recommendations = Vec::new();

        // Analyze specific issues
        if summary.drop_rate_percent > self.thresholds.max_drop_rate_percent {
            issues.push(format!("High drop rate: {:.2}%", summary.drop_rate_percent));
            recommendations.push("Consider increasing ring buffer size or reducing event rate".to_string());
        }

        if summary.avg_processing_time_ns > (self.thresholds.max_avg_latency_ms * 1_000_000.0) as u64 {
            issues.push(format!("High latency: {:.2}ms", summary.avg_processing_time_ns as f64 / 1_000_000.0));
            recommendations.push("Optimize event processing pipeline or increase batch size".to_string());
        }

        if summary.memory_usage_mb > self.thresholds.max_memory_usage_mb {
            issues.push(format!("High memory usage: {:.1}MB", summary.memory_usage_mb));
            recommendations.push("Check for memory leaks or reduce buffer sizes".to_string());
        }

        HealthReport {
            status: overall_status,
            summary,
            issues,
            recommendations,
            timestamp: SystemTime::now(),
        }
    }
}

/// Detailed health report
#[derive(Debug)]
pub struct HealthReport {
    pub status: HealthStatus,
    pub summary: MetricsSummary,
    pub issues: Vec<String>,
    pub recommendations: Vec<String>,
    pub timestamp: SystemTime,
}

impl HealthReport {
    /// Convert to JSON string for API responses
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| SentinelError::Serialization { 
                context: "health report".to_string(),
                source: Box::new(e)
            })
    }
}

// Make HealthReport serializable
impl serde::Serialize for HealthReport {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        
        let mut state = serializer.serialize_struct("HealthReport", 5)?;
        
        let status_str = match self.status {
            HealthStatus::Healthy => "healthy",
            HealthStatus::Warning => "warning", 
            HealthStatus::Critical => "critical",
            HealthStatus::Unknown => "unknown",
        };
        state.serialize_field("status", status_str)?;
        
        state.serialize_field("events_processed", &self.summary.events_processed)?;
        state.serialize_field("events_dropped", &self.summary.events_dropped)?;
        state.serialize_field("drop_rate_percent", &self.summary.drop_rate_percent)?;
        state.serialize_field("avg_processing_time_ms", &(self.summary.avg_processing_time_ns as f64 / 1_000_000.0))?;
        state.serialize_field("memory_usage_mb", &self.summary.memory_usage_mb)?;
        state.serialize_field("cpu_usage_percent", &self.summary.cpu_usage_percent)?;
        state.serialize_field("uptime_seconds", &self.summary.uptime_seconds)?;
        state.serialize_field("error_count", &self.summary.error_count)?;
        state.serialize_field("issues", &self.issues)?;
        state.serialize_field("recommendations", &self.recommendations)?;
        
        let timestamp_secs = self.timestamp
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        state.serialize_field("timestamp", &timestamp_secs)?;
        
        state.end()
    }
}