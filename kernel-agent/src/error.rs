// kernel-agent/src/error.rs
// Comprehensive error handling system for SentinelEdge

use std::fmt;
use std::result;
use thiserror::Error;

/// Main error type for the SentinelEdge kernel agent
#[derive(Error, Debug)]
pub enum SentinelError {
    /// eBPF program loading or compilation errors
    #[error("eBPF error: {message} (context: {context})")]
    EbpfError { message: String, context: String },

    /// eBPF program loading errors
    #[error("eBPF program load failed: {0}")]
    EbpfLoad(String),

    /// Parse errors for events or data
    #[error("Parse error: {0}")]
    Parse(String),

    /// Configuration validation errors (simplified)
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// Performance test failures
    #[error("Performance test failed: {0}")]
    PerformanceTest(String),

    /// Ring buffer related errors
    #[error("Ring buffer error: {kind}")]
    RingBuffer { kind: RingBufferErrorKind },

    /// Event parsing and processing errors
    #[error("Event processing error: {message} (event_type: {event_type})")]
    EventProcessing { message: String, event_type: String },

    /// Configuration validation errors
    #[error("Configuration error: {field} - {message}")]
    Config { field: String, message: String },

    /// Permission or system access errors
    #[error("Permission denied: {operation} (details: {details})")]
    Permission { operation: String, details: String },

    /// Resource exhaustion errors
    #[error("Resource exhausted: {resource} (limit: {limit}, current: {current})")]
    ResourceExhausted { 
        resource: String, 
        limit: u64, 
        current: u64 
    },

    /// Network or I/O related errors
    #[error("I/O error: {operation} failed - {source}")]
    Io { 
        operation: String, 
        #[source] 
        source: std::io::Error 
    },

    /// Timeout errors
    #[error("Operation timed out: {operation} (timeout: {timeout_ms}ms)")]
    Timeout { operation: String, timeout_ms: u64 },

    /// Serialization/deserialization errors
    #[error("Serialization error: {context} - {source}")]
    Serialization { 
        context: String, 
        #[source] 
        source: Box<dyn std::error::Error + Send + Sync> 
    },

    /// Critical system errors that should cause shutdown
    #[error("Critical system error: {message} (should_shutdown: {should_shutdown})")]
    Critical { message: String, should_shutdown: bool },
}

/// Specific ring buffer error types
#[derive(Error, Debug)]
pub enum RingBufferErrorKind {
    #[error("Ring buffer is full (capacity: {capacity}, pending: {pending})")]
    Full { capacity: usize, pending: usize },
    
    #[error("Ring buffer polling failed")]
    PollFailed,
    
    #[error("Invalid ring buffer configuration: {reason}")]
    InvalidConfig { reason: String },
    
    #[error("Ring buffer consumer disconnected")]
    ConsumerDisconnected,
}

/// Result type alias for convenience
pub type Result<T> = result::Result<T, SentinelError>;

/// Error recovery strategy
#[derive(Debug, Clone)]
pub enum RecoveryStrategy {
    /// Retry the operation with exponential backoff
    Retry { max_attempts: u32, initial_delay_ms: u64 },
    /// Fall back to a degraded mode
    Fallback { description: String },
    /// Continue processing but log the error
    Continue,
    /// Shut down the component or system
    Shutdown,
}

/// Error context for better debugging and monitoring
#[derive(Debug, Clone)]
pub struct ErrorContext {
    pub component: String,
    pub operation: String,
    pub timestamp: std::time::SystemTime,
    pub process_id: Option<u32>,
    pub thread_id: Option<std::thread::ThreadId>,
    pub additional_data: std::collections::HashMap<String, String>,
}

impl ErrorContext {
    pub fn new(component: &str, operation: &str) -> Self {
        Self {
            component: component.to_string(),
            operation: operation.to_string(),
            timestamp: std::time::SystemTime::now(),
            process_id: Some(std::process::id()),
            thread_id: Some(std::thread::current().id()),
            additional_data: std::collections::HashMap::new(),
        }
    }

    pub fn with_data(mut self, key: &str, value: &str) -> Self {
        self.additional_data.insert(key.to_string(), value.to_string());
        self
    }
}

/// Trait for error recovery
pub trait ErrorRecovery {
    fn recovery_strategy(&self) -> RecoveryStrategy;
    fn is_recoverable(&self) -> bool;
    fn error_category(&self) -> ErrorCategory;
}

#[derive(Debug, Clone, PartialEq)]
pub enum ErrorCategory {
    Transient,    // Temporary errors that might resolve
    Permanent,    // Errors that won't resolve without intervention
    Critical,     // Errors that require immediate attention
    Warning,      // Non-critical errors for monitoring
}

impl ErrorRecovery for SentinelError {
    fn recovery_strategy(&self) -> RecoveryStrategy {
        match self {
            SentinelError::RingBuffer { kind } => match kind {
                RingBufferErrorKind::Full { .. } => RecoveryStrategy::Retry { 
                    max_attempts: 3, 
                    initial_delay_ms: 100 
                },
                RingBufferErrorKind::PollFailed => RecoveryStrategy::Retry { 
                    max_attempts: 5, 
                    initial_delay_ms: 50 
                },
                _ => RecoveryStrategy::Fallback { 
                    description: "Switch to backup ring buffer".to_string() 
                },
            },
            SentinelError::EventProcessing { .. } => RecoveryStrategy::Continue,
            SentinelError::Permission { .. } => RecoveryStrategy::Shutdown,
            SentinelError::ResourceExhausted { .. } => RecoveryStrategy::Retry { 
                max_attempts: 2, 
                initial_delay_ms: 1000 
            },
            SentinelError::Timeout { .. } => RecoveryStrategy::Retry { 
                max_attempts: 3, 
                initial_delay_ms: 200 
            },
            SentinelError::Critical { should_shutdown, .. } => {
                if *should_shutdown {
                    RecoveryStrategy::Shutdown
                } else {
                    RecoveryStrategy::Fallback { 
                        description: "Switch to safe mode".to_string() 
                    }
                }
            },
            _ => RecoveryStrategy::Continue,
        }
    }

    fn is_recoverable(&self) -> bool {
        !matches!(self, 
            SentinelError::Permission { .. } | 
            SentinelError::Critical { should_shutdown: true, .. }
        )
    }

    fn error_category(&self) -> ErrorCategory {
        match self {
            SentinelError::Critical { .. } => ErrorCategory::Critical,
            SentinelError::Permission { .. } => ErrorCategory::Critical,
            SentinelError::ResourceExhausted { .. } => ErrorCategory::Transient,
            SentinelError::Timeout { .. } => ErrorCategory::Transient,
            SentinelError::RingBuffer { .. } => ErrorCategory::Transient,
            SentinelError::EventProcessing { .. } => ErrorCategory::Warning,
            _ => ErrorCategory::Permanent,
        }
    }
}

/// Helper macros for error creation
#[macro_export]
macro_rules! sentinel_error {
    (ebpf, $msg:expr, $ctx:expr) => {
        SentinelError::EbpfError {
            message: $msg.to_string(),
            context: $ctx.to_string(),
        }
    };
    (config, $field:expr, $msg:expr) => {
        SentinelError::Config {
            field: $field.to_string(),
            message: $msg.to_string(),
        }
    };
    (permission, $op:expr, $details:expr) => {
        SentinelError::Permission {
            operation: $op.to_string(),
            details: $details.to_string(),
        }
    };
}

/// Convert common error types
impl From<std::io::Error> for SentinelError {
    fn from(err: std::io::Error) -> Self {
        SentinelError::Io {
            operation: "unknown".to_string(),
            source: err,
        }
    }
}

impl From<serde_json::Error> for SentinelError {
    fn from(err: serde_json::Error) -> Self {
        SentinelError::Serialization {
            context: "JSON processing".to_string(),
            source: Box::new(err),
        }
    }
}

impl From<anyhow::Error> for SentinelError {
    fn from(err: anyhow::Error) -> Self {
        SentinelError::EbpfLoad(err.to_string())
    }
}

impl From<tokio::time::error::Elapsed> for SentinelError {
    fn from(_: tokio::time::error::Elapsed) -> Self {
        SentinelError::Timeout {
            operation: "async operation".to_string(),
            timeout_ms: 0, // Will be filled by the caller
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_recovery_strategy() {
        let ring_buffer_error = SentinelError::RingBuffer {
            kind: RingBufferErrorKind::Full { capacity: 1024, pending: 1024 }
        };
        
        assert!(ring_buffer_error.is_recoverable());
        assert_eq!(ring_buffer_error.error_category(), ErrorCategory::Transient);
        
        match ring_buffer_error.recovery_strategy() {
            RecoveryStrategy::Retry { max_attempts, .. } => {
                assert_eq!(max_attempts, 3);
            }
            _ => panic!("Expected retry strategy"),
        }
    }

    #[test]
    fn test_error_context() {
        let ctx = ErrorContext::new("ring_buffer", "poll")
            .with_data("buffer_size", "1024")
            .with_data("events_pending", "512");
        
        assert_eq!(ctx.component, "ring_buffer");
        assert_eq!(ctx.operation, "poll");
        assert!(ctx.additional_data.contains_key("buffer_size"));
    }

    #[test]
    fn test_error_categorization() {
        let critical_error = SentinelError::Critical {
            message: "System failure".to_string(),
            should_shutdown: true,
        };
        
        assert!(!critical_error.is_recoverable());
        assert_eq!(critical_error.error_category(), ErrorCategory::Critical);
    }
}