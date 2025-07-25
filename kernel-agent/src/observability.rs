// kernel-agent/src/observability.rs
// Comprehensive observability and monitoring for SentinelEdge

use crate::error::*;
use crate::EbpfMetrics;
use metrics::{Counter, Gauge, Histogram};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, info, warn, error, instrument};

/// Comprehensive metrics collector for SentinelEdge
pub struct SentinelMetrics {
    // Event processing metrics
    events_processed_total: u64,
    events_dropped_total: u64,
    events_by_type: HashMap<String, u64>,
    
    // Performance metrics
    event_processing_times: Vec<Duration>,
    ring_buffer_utilization: f64,
    memory_usage_bytes: u64,
    
    // Error metrics
    errors_by_type: HashMap<String, u64>,
    error_recovery_attempts: u64,
    
    // System health metrics
    system_uptime_seconds: u64,
    cpu_usage_percent: f64,
    thread_count: u64,
    
    // Custom metrics storage
    custom_metrics: Arc<RwLock<HashMap<String, f64>>>,
    
    // Metrics metadata
    start_time: Instant,
    last_update: Arc<RwLock<Instant>>,
}

impl SentinelMetrics {
    /// Create a new metrics collector
    pub fn new() -> Self {
        Self {
            events_processed_total: 0,
            events_dropped_total: 0,
            events_by_type: HashMap::new(),
            
            event_processing_times: Vec::with_capacity(1000),
            ring_buffer_utilization: 0.0,
            memory_usage_bytes: 0,
            
            errors_by_type: HashMap::new(),
            error_recovery_attempts: 0,
            
            system_uptime_seconds: 0,
            cpu_usage_percent: 0.0,
            thread_count: 1,
            
            custom_metrics: Arc::new(RwLock::new(HashMap::new())),
            
            start_time: Instant::now(),
            last_update: Arc::new(RwLock::new(Instant::now())),
        }
    }

    /// Record an event being processed
    #[instrument(skip(self))]
    pub async fn record_event_processed(&self, event_type: &str, processing_duration: Duration) {
        self.events_processed_total.increment(1);
        self.event_processing_duration.record(processing_duration.as_secs_f64());
        
        // Track events by type
        let counter = self.events_by_type.get(event_type)
            .cloned()
            .unwrap_or_else(|| {
                metrics::counter!("sentinel_events_by_type_total", "type" => event_type.to_string())
            });
        counter.increment(1);
        
        debug!("Recorded event: type={}, duration={:?}", event_type, processing_duration);
    }

    /// Record an event being dropped
    #[instrument(skip(self))]
    pub async fn record_event_dropped(&self, reason: &str) {
        self.events_dropped_total.increment(1);
        
        let counter = metrics::counter!(
            "sentinel_events_dropped_by_reason_total", 
            "reason" => reason.to_string()
        );
        counter.increment(1);
        
        warn!("Event dropped: reason={}", reason);
    }

    /// Record an error occurrence
    #[instrument(skip(self))]
    pub async fn record_error(&self, error: &SentinelError) {
        let error_type = match error {
            SentinelError::EbpfError { .. } => "ebpf",
            SentinelError::RingBuffer { .. } => "ring_buffer",
            SentinelError::EventProcessing { .. } => "event_processing",
            SentinelError::Config { .. } => "config",
            SentinelError::Permission { .. } => "permission",
            SentinelError::ResourceExhausted { .. } => "resource_exhausted",
            SentinelError::Io { .. } => "io",
            SentinelError::Timeout { .. } => "timeout",
            SentinelError::Serialization { .. } => "serialization",
            SentinelError::Critical { .. } => "critical",
        };

        let counter = self.errors_by_type.get(error_type)
            .cloned()
            .unwrap_or_else(|| {
                metrics::counter!("sentinel_errors_by_type_total", "type" => error_type.to_string())
            });
        counter.increment(1);
        
        error!("Recorded error: type={}, error={}", error_type, error);
    }

    /// Record error recovery attempt
    pub async fn record_recovery_attempt(&self, successful: bool) {
        self.error_recovery_attempts.increment(1);
        
        let counter = metrics::counter!(
            "sentinel_error_recovery_by_result_total",
            "result" => if successful { "success" } else { "failure" }
        );
        counter.increment(1);
    }

    /// Update system metrics from EbpfMetrics
    #[instrument(skip(self, metrics))]
    pub async fn update_from_ebpf_metrics(&self, metrics: &EbpfMetrics) {
        self.system_uptime_seconds.set(metrics.uptime_seconds as f64);
        
        // Calculate ring buffer utilization (approximate)
        if metrics.events_processed > 0 {
            let utilization = (metrics.events_dropped as f64 / 
                (metrics.events_processed + metrics.events_dropped) as f64) * 100.0;
            self.ring_buffer_utilization.set(utilization);
        }
        
        // Update memory usage if available
        if let Ok(memory_info) = get_memory_usage().await {
            self.memory_usage_bytes.set(memory_info.rss_bytes as f64);
        }
        
        // Update CPU usage
        if let Ok(cpu_usage) = get_cpu_usage().await {
            self.cpu_usage_percent.set(cpu_usage);
        }
        
        // Update thread count
        if let Ok(thread_count) = get_thread_count().await {
            self.thread_count.set(thread_count as f64);
        }
        
        *self.last_update.write().await = Instant::now();
    }

    /// Set a custom metric value
    pub async fn set_custom_metric(&self, name: &str, value: f64) {
        let mut custom = self.custom_metrics.write().await;
        custom.insert(name.to_string(), value);
        
        // Also record to the global metrics registry
        let gauge = metrics::gauge!(format!("sentinel_custom_{}", name));
        gauge.set(value);
    }

    /// Get current metrics summary
    pub async fn get_metrics_summary(&self) -> MetricsSummary {
        let uptime = self.start_time.elapsed();
        let last_update = *self.last_update.read().await;
        let custom = self.custom_metrics.read().await.clone();
        
        MetricsSummary {
            uptime_seconds: uptime.as_secs(),
            last_update_seconds_ago: last_update.elapsed().as_secs(),
            custom_metrics: custom,
            memory_usage_mb: get_memory_usage().await
                .map(|m| m.rss_bytes / 1024 / 1024)
                .unwrap_or(0),
            cpu_usage_percent: get_cpu_usage().await.unwrap_or(0.0),
            thread_count: get_thread_count().await.unwrap_or(0),
        }
    }
}

impl Default for SentinelMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Summary of current metrics
#[derive(Debug, Clone)]
pub struct MetricsSummary {
    pub uptime_seconds: u64,
    pub last_update_seconds_ago: u64,
    pub custom_metrics: HashMap<String, f64>,
    pub memory_usage_mb: u64,
    pub cpu_usage_percent: f64,
    pub thread_count: u64,
}

/// Memory usage information
#[derive(Debug, Clone)]
pub struct MemoryInfo {
    pub rss_bytes: u64,      // Resident Set Size
    pub vms_bytes: u64,      // Virtual Memory Size
    pub heap_bytes: u64,     // Heap usage
}

/// Health check status
#[derive(Debug, Clone, PartialEq)]
pub enum HealthStatus {
    Healthy,
    Degraded { reason: String },
    Unhealthy { reason: String },
}

/// Comprehensive health checker
pub struct HealthChecker {
    metrics: Arc<SentinelMetrics>,
    last_check: Arc<RwLock<Instant>>,
    health_status: Arc<RwLock<HealthStatus>>,
    check_interval: Duration,
}

impl HealthChecker {
    /// Create a new health checker
    pub fn new(metrics: Arc<SentinelMetrics>) -> Self {
        Self {
            metrics,
            last_check: Arc::new(RwLock::new(Instant::now())),
            health_status: Arc::new(RwLock::new(HealthStatus::Healthy)),
            check_interval: Duration::from_secs(30),
        }
    }

    /// Start periodic health checks
    #[instrument(skip(self))]
    pub async fn start_periodic_checks(&self) -> Result<()> {
        let metrics = Arc::clone(&self.metrics);
        let last_check = Arc::clone(&self.last_check);  
        let health_status = Arc::clone(&self.health_status);
        let check_interval = self.check_interval;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(check_interval);
            
            loop {
                interval.tick().await;
                
                match Self::perform_health_check(&metrics).await {
                    Ok(status) => {
                        *health_status.write().await = status.clone();
                        *last_check.write().await = Instant::now();
                        
                        match status {
                            HealthStatus::Healthy => {
                                debug!("Health check passed");
                            }
                            HealthStatus::Degraded { ref reason } => {
                                warn!("System degraded: {}", reason);
                            }
                            HealthStatus::Unhealthy { ref reason } => {
                                error!("System unhealthy: {}", reason);
                            }
                        }
                    }
                    Err(e) => {
                        error!("Health check failed: {}", e);
                        *health_status.write().await = HealthStatus::Unhealthy {
                            reason: format!("Health check error: {}", e)
                        };
                    }
                }
            }
        });

        info!("Started periodic health checks every {:?}", check_interval);
        Ok(())
    }

    /// Perform a single health check
    async fn perform_health_check(metrics: &SentinelMetrics) -> Result<HealthStatus> {
        let summary = metrics.get_metrics_summary().await;
        
        // Check memory usage
        if summary.memory_usage_mb > 1024 { // More than 1GB
            return Ok(HealthStatus::Degraded {
                reason: format!("High memory usage: {}MB", summary.memory_usage_mb)
            });
        }
        
        // Check CPU usage
        if summary.cpu_usage_percent > 90.0 {
            return Ok(HealthStatus::Degraded {
                reason: format!("High CPU usage: {:.1}%", summary.cpu_usage_percent)
            });
        }
        
        // Check if metrics are being updated
        if summary.last_update_seconds_ago > 300 { // 5 minutes
            return Ok(HealthStatus::Unhealthy {
                reason: "Metrics not updating".to_string()
            });
        }
        
        // Check thread count
        if summary.thread_count > 1000 {
            return Ok(HealthStatus::Degraded {
                reason: format!("High thread count: {}", summary.thread_count)
            });
        }
        
        Ok(HealthStatus::Healthy)
    }

    /// Get current health status
    pub async fn get_health_status(&self) -> HealthStatus {
        self.health_status.read().await.clone()
    }

    /// Get health check details
    pub async fn get_health_details(&self) -> HealthCheckDetails {
        let status = self.get_health_status().await;
        let last_check = *self.last_check.read().await;
        let summary = self.metrics.get_metrics_summary().await;
        
        HealthCheckDetails {
            status,
            last_check_seconds_ago: last_check.elapsed().as_secs(),
            metrics_summary: summary,
            check_interval_seconds: self.check_interval.as_secs(),
        }
    }
}

/// Detailed health check information
#[derive(Debug, Clone)]
pub struct HealthCheckDetails {
    pub status: HealthStatus,
    pub last_check_seconds_ago: u64,
    pub metrics_summary: MetricsSummary,
    pub check_interval_seconds: u64,
}

/// Get current memory usage information
async fn get_memory_usage() -> Result<MemoryInfo> {
    #[cfg(target_os = "linux")]
    {
        use std::fs;
        
        let contents = fs::read_to_string("/proc/self/status")
            .map_err(|e| SentinelError::Io {
                operation: "read /proc/self/status".to_string(),
                source: e,
            })?;
        
        let mut rss_bytes = 0;
        let mut vms_bytes = 0;
        
        for line in contents.lines() {
            if line.starts_with("VmRSS:") {
                if let Some(kb_str) = line.split_whitespace().nth(1) {
                    rss_bytes = kb_str.parse::<u64>().unwrap_or(0) * 1024;
                }
            } else if line.starts_with("VmSize:") {
                if let Some(kb_str) = line.split_whitespace().nth(1) {
                    vms_bytes = kb_str.parse::<u64>().unwrap_or(0) * 1024;
                }
            }
        }
        
        Ok(MemoryInfo {
            rss_bytes,
            vms_bytes,
            heap_bytes: 0, // Not easily available on Linux
        })
    }
    
    #[cfg(not(target_os = "linux"))]
    {
        // Fallback for non-Linux systems
        Ok(MemoryInfo {
            rss_bytes: 0,
            vms_bytes: 0,
            heap_bytes: 0,
        })
    }
}

/// Get current CPU usage percentage
async fn get_cpu_usage() -> Result<f64> {
    #[cfg(target_os = "linux")]
    {
        use std::fs;
        use std::time::Duration;
        
        // Read CPU stats twice with a small interval
        let stats1 = read_cpu_stats().await?;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let stats2 = read_cpu_stats().await?;
        
        let total_diff = stats2.total - stats1.total;
        let idle_diff = stats2.idle - stats1.idle;
        
        if total_diff > 0 {
            let usage = ((total_diff - idle_diff) as f64 / total_diff as f64) * 100.0;
            Ok(usage.min(100.0).max(0.0))
        } else {
            Ok(0.0)
        }
    }
    
    #[cfg(not(target_os = "linux"))]
    {
        Ok(0.0) // Fallback for non-Linux systems
    }
}

#[cfg(target_os = "linux")]
struct CpuStats {
    total: u64,
    idle: u64,
}

#[cfg(target_os = "linux")]
async fn read_cpu_stats() -> Result<CpuStats> {
    use std::fs;
    
    let contents = fs::read_to_string("/proc/stat")
        .map_err(|e| SentinelError::Io {
            operation: "read /proc/stat".to_string(),
            source: e,
        })?;
    
    if let Some(line) = contents.lines().next() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 5 && parts[0] == "cpu" {
            let user: u64 = parts[1].parse().unwrap_or(0);
            let nice: u64 = parts[2].parse().unwrap_or(0);
            let system: u64 = parts[3].parse().unwrap_or(0);
            let idle: u64 = parts[4].parse().unwrap_or(0);
            let iowait: u64 = parts.get(5).and_then(|s| s.parse().ok()).unwrap_or(0);
            
            let total = user + nice + system + idle + iowait;
            
            return Ok(CpuStats { total, idle });
        }
    }
    
    Err(SentinelError::EventProcessing {
        message: "Failed to parse /proc/stat".to_string(),
        event_type: "cpu_stats".to_string(),
    })
}

/// Get current thread count
async fn get_thread_count() -> Result<u64> {
    #[cfg(target_os = "linux")]
    {
        use std::fs;
        
        match fs::read_dir("/proc/self/task") {
            Ok(entries) => {
                let count = entries.count() as u64;
                Ok(count)
            }
            Err(e) => {
                warn!("Failed to read thread count: {}", e);
                Ok(0)
            }
        }
    }
    
    #[cfg(not(target_os = "linux"))]
    {
        Ok(1) // Fallback
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_metrics_collection() {
        let metrics = SentinelMetrics::new();
        
        // Record some events
        metrics.record_event_processed("exec", Duration::from_millis(10)).await;
        metrics.record_event_processed("netconn", Duration::from_millis(5)).await;
        metrics.record_event_dropped("rate_limit").await;
        
        let summary = metrics.get_metrics_summary().await;
        assert!(summary.uptime_seconds >= 0);
        assert!(summary.last_update_seconds_ago < 2); // Should be very recent
    }

    #[tokio::test]
    async fn test_health_checker() {
        let metrics = Arc::new(SentinelMetrics::new());
        let health_checker = HealthChecker::new(Arc::clone(&metrics));
        
        let status = health_checker.get_health_status().await;
        assert_eq!(status, HealthStatus::Healthy);
        
        let details = health_checker.get_health_details().await;
        assert!(matches!(details.status, HealthStatus::Healthy));
    }

    #[tokio::test]
    async fn test_error_recording() {
        let metrics = SentinelMetrics::new();
        
        let error = SentinelError::EventProcessing {
            message: "Test error".to_string(),
            event_type: "test".to_string(),
        };
        
        metrics.record_error(&error).await;
        // Test that no panic occurs - actual metric values are hard to test
    }

    #[tokio::test]
    async fn test_custom_metrics() {
        let metrics = SentinelMetrics::new();
        
        metrics.set_custom_metric("test_metric", 42.0).await;
        
        let summary = metrics.get_metrics_summary().await;
        assert_eq!(summary.custom_metrics.get("test_metric"), Some(&42.0));
    }
}