// kernel-agent/src/lib.rs
// Event definitions and data structures

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock, Semaphore};
use tokio::time::{interval, timeout, Instant};
use tokio_stream::{wrappers::ReceiverStream, Stream, StreamExt};
use tracing::{debug, info, warn, instrument, error};

mod error;
mod safe_parser;
mod observability_simple;
mod config_validation;
pub use error::*;
pub use safe_parser::{SafeEventParser, safe_cstr_to_string, validate_event_data};
pub use observability_simple::{SentinelMetrics, HealthChecker, HealthStatus, MetricsSummary};
pub use config_validation::{ConfigValidator, ValidationReport, SystemConstraints};

#[cfg(target_os = "linux")]
use anyhow::Context;
#[cfg(target_os = "linux")]
use libbpf_rs::{RingBufferBuilder, Object, ObjectBuilder};

pub mod events;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod integration_tests;
#[cfg(test)]
mod real_integration_tests;
#[cfg(test)]
mod real_ebpf_tests;

pub use events::*;
pub use error::{SentinelError, Result};

/// High-performance eBPF kernel monitoring agent
/// 
/// The `EbpfLoader` is the main entry point for SentinelEdge kernel monitoring.
/// It provides asynchronous event processing, configurable ring buffers, and 
/// comprehensive error handling.
/// 
/// # Examples
/// 
/// Basic usage:
/// ```rust
/// use kernel_agent::{EbpfLoader, EbpfConfig};
/// 
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let mut loader = EbpfLoader::new();
///     loader.initialize().await?;
///     
///     let mut event_stream = loader.event_stream().await?;
///     while let Some(event) = event_stream.next().await {
///         println!("Received event: {:?}", event);
///     }
///     
///     loader.shutdown().await?;
///     Ok(())
/// }
/// ```
/// 
/// With custom configuration:
/// ```rust
/// use kernel_agent::{EbpfLoader, EbpfConfig};
/// 
/// let config = EbpfConfig {
///     ring_buffer_size: 512 * 1024, // 512KB buffer
///     max_events_per_sec: 5000,     // Rate limiting
///     enable_backpressure: true,     // Handle overload
///     ..Default::default()
/// };
/// 
/// let mut loader = EbpfLoader::with_config(config);
/// ```
pub struct EbpfLoader {
    config: EbpfConfig,
    pub event_sender: mpsc::Sender<RawEvent>,
    pub event_receiver: Arc<RwLock<Option<mpsc::Receiver<RawEvent>>>>,
    pub metrics: Arc<RwLock<EbpfMetrics>>,
    shutdown_signal: Arc<tokio::sync::Notify>,
    rate_limiter: Arc<Semaphore>,
    #[cfg(target_os = "linux")]
    _object: Option<Object>,
}

/// Configuration for the eBPF loader
/// 
/// This structure controls various aspects of the eBPF monitoring system,
/// including buffer sizes, rate limiting, and performance optimizations.
#[derive(Debug, Clone)]
pub struct EbpfConfig {
    pub ring_buffer_size: usize,
    pub event_batch_size: usize,
    pub poll_timeout_ms: u64,
    pub max_events_per_sec: usize,
    pub enable_backpressure: bool,
    pub auto_recovery: bool,
    pub metrics_interval_sec: u64,
    // High-performance processing options
    pub ring_buffer_poll_timeout_us: Option<u64>,
    pub batch_size: Option<usize>,
    pub batch_timeout_us: Option<u64>,
}

impl Default for EbpfConfig {
    fn default() -> Self {
        Self {
            ring_buffer_size: 256 * 1024,
            event_batch_size: 100,
            poll_timeout_ms: 100,
            max_events_per_sec: 10000,
            enable_backpressure: true,
            auto_recovery: true,
            metrics_interval_sec: 60,
            // High-performance defaults
            ring_buffer_poll_timeout_us: Some(100),  // 100 microseconds for low latency
            batch_size: Some(64),                    // Optimized batch size
            batch_timeout_us: Some(1000),            // 1ms max batch timeout
        }
    }
}

/// Runtime metrics for the eBPF monitoring system
/// 
/// These metrics provide insight into system performance, event processing
/// rates, error conditions, and resource utilization.
#[derive(Debug, Clone, Default)]
pub struct EbpfMetrics {
    pub events_processed: u64,
    pub events_dropped: u64,
    pub ring_buffer_full_count: u64,
    pub processing_errors: u64,
    pub average_latency_ns: u64,
    pub peak_events_per_sec: u64,
    pub uptime_seconds: u64,
    pub last_event_timestamp: Option<Instant>,
}

/// Raw events received from the eBPF kernel programs
/// 
/// These events represent different types of kernel activities that are
/// monitored by the SentinelEdge system.
#[derive(Debug, Clone)]
pub enum RawEvent {
    Exec(ExecEvent),
    NetConn(NetConnEvent),
    FileOp(FileOpEvent),
    Error(EventError),
    Heartbeat(HeartbeatEvent),
}

/// Process execution event from kernel
/// 
/// Captures information about process creation, including process IDs,
/// user context, command name, and execution parameters.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct ExecEvent {
    pub timestamp: u64,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: [u8; 16],
    pub filename: [u8; 256],
    pub args_count: u8,
    pub exit_code: i32,
}

/// Network connection event from kernel
/// 
/// Captures network connection attempts and established connections,
/// including source/destination addresses, ports, and protocols.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct NetConnEvent {
    pub timestamp: u64,
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; 16],
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
    pub protocol: u8,
    pub direction: u8, // 0=outbound, 1=inbound
}

/// File system operation event from kernel
/// 
/// Captures file system activities including file opens, reads, writes,
/// and metadata operations.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct FileOpEvent {
    pub timestamp: u64,
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; 16],
    pub operation: u32,
    pub filename: [u8; 256],
    pub mode: u32,
    pub size: u64,
    pub flags: u32,
}

#[derive(Debug, Clone)]
pub struct EventError {
    pub timestamp: u64,
    pub error_type: ErrorType,
    pub message: String,
    pub context: String,
}

#[derive(Debug, Clone)]
pub enum ErrorType {
    RingBufferFull,
    ParseError,
    PermissionDenied,
    ResourceExhausted,
    KernelError,
}

#[derive(Debug, Clone)]
pub struct HeartbeatEvent {
    pub timestamp: u64,
    pub sequence: u64,
    pub metrics: EbpfMetrics,
}

impl EbpfLoader {
    /// Create a new eBPF loader with default configuration
    /// 
    /// # Examples
    /// 
    /// ```rust
    /// use kernel_agent::EbpfLoader;
    /// 
    /// let loader = EbpfLoader::new();
    /// ```
    pub fn new() -> Self {
        Self::with_config(EbpfConfig::default())
    }

    /// Create a new eBPF loader with custom configuration
    /// 
    /// # Arguments
    /// 
    /// * `config` - Configuration parameters for the eBPF system
    /// 
    /// # Examples
    /// 
    /// ```rust
    /// use kernel_agent::{EbpfLoader, EbpfConfig};
    /// 
    /// let config = EbpfConfig {
    ///     ring_buffer_size: 1024 * 1024, // 1MB buffer
    ///     max_events_per_sec: 10000,     // High throughput
    ///     ..Default::default()
    /// };
    /// 
    /// let loader = EbpfLoader::with_config(config);
    /// ```
    pub fn with_config(config: EbpfConfig) -> Self {
        let (event_sender, event_receiver) = mpsc::channel(config.event_batch_size * 2);
        let rate_limiter = Arc::new(Semaphore::new(config.max_events_per_sec));

        Self {
            config,
            event_sender,
            event_receiver: Arc::new(RwLock::new(Some(event_receiver))),
            metrics: Arc::new(RwLock::new(EbpfMetrics::default())),
            shutdown_signal: Arc::new(tokio::sync::Notify::new()),
            rate_limiter,
            #[cfg(target_os = "linux")]
            _object: None,
        }
    }

    /// Initialize the eBPF monitoring system
    /// 
    /// This method loads the eBPF programs into the kernel and starts
    /// the event processing pipeline. On non-Linux systems or when
    /// lacking permissions, it falls back to simulation mode.
    /// 
    /// # Returns
    /// 
    /// * `Ok(())` - System initialized successfully
    /// * `Err(SentinelError)` - Initialization failed
    /// 
    /// # Errors
    /// 
    /// * `SentinelError::Permission` - Insufficient privileges (requires root on Linux)
    /// * `SentinelError::EbpfError` - eBPF program loading failed
    /// * `SentinelError::ResourceExhausted` - System resources unavailable
    /// 
    /// # Examples
    /// 
    /// ```rust
    /// use kernel_agent::EbpfLoader;
    /// 
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let mut loader = EbpfLoader::new();
    ///     loader.initialize().await?;
    ///     println!("eBPF system initialized successfully");
    ///     Ok(())
    /// }
    /// ```
    #[instrument(skip(self))]
    pub async fn initialize(&mut self) -> Result<()> {
        info!("🔧 Initializing high-performance async eBPF loader...");

        #[cfg(target_os = "linux")]
        {
            if !nix::unistd::Uid::effective().is_root() {
                return Err(SentinelError::Permission {
                    operation: "eBPF program loading".to_string(),
                    details: "Root privileges required to load eBPF programs".to_string(),
                });
            }

            match self.initialize_linux().await {
                Ok(object) => {
                    info!("✅ eBPF program loaded successfully, starting async event processing");
                    self._object = Some(object);
                    
                    // Start async tasks
                    self.start_background_tasks().await?;
                }
                Err(e) => {
                    error!("⚠️  eBPF program loading failed: {}", e);
                    warn!("🔄 Starting simulation mode");
                    self.start_mock_mode().await?;
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            warn!("⚠️  Non-Linux system, starting simulation mode");
            self.start_mock_mode().await?;
        }

        Ok(())
    }

    #[cfg(target_os = "linux")]
    async fn initialize_linux(&self) -> Result<Object> {
        let mut object = ObjectBuilder::default()
            .open_file("kernel-agent/src/sentinel.bpf.o")
            .context("Cannot open eBPF object file")?
            .load()
            .context("Cannot load eBPF program")?;

        // Attach all programs in the object
        for prog in object.progs_iter_mut() {
            if let Err(e) = prog.attach() {
                warn!("Failed to attach program {}: {}", prog.name(), e);
            } else {
                info!("Successfully attached program: {}", prog.name());
            }
        }

        let rb_map = object
            .map("events")
            .context("Cannot find ring buffer map")?;

        // Create async ring buffer processor  
        let sender = self.event_sender.clone();
        let metrics = Arc::clone(&self.metrics);
        let rate_limiter = Arc::clone(&self.rate_limiter);
        let shutdown = Arc::clone(&self.shutdown_signal);
        let config = self.config.clone();

        // Process ring buffer in current thread context
        Self::setup_ring_buffer_processor(
            rb_map,
            sender,
            metrics,
            rate_limiter,
            shutdown,
            config,
        ).await?;

        Ok(object)
    }

    #[cfg(target_os = "linux")]
    async fn setup_ring_buffer_processor(
        rb_map: &libbpf_rs::Map,
        sender: mpsc::Sender<RawEvent>,
        metrics: Arc<RwLock<EbpfMetrics>>,
        rate_limiter: Arc<Semaphore>,
        shutdown: Arc<tokio::sync::Notify>,
        config: EbpfConfig,
    ) -> Result<()> {
        info!("📡 Setting up high-performance ring buffer processor");

        // Create a high-throughput channel for raw events from ring buffer
        let (raw_event_tx, raw_event_rx) = 
            tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();

        // Create ring buffer builder and add callback
        let mut rb_builder = RingBufferBuilder::new();
        let tx_clone = raw_event_tx.clone();
        let _ = rb_builder.add(rb_map, move |data: &[u8]| {
            // High-performance zero-copy event forwarding
            if tx_clone.send(data.to_vec()).is_err() {
                // Channel closed, signal to stop
                return -1;
            }
            0
        });

        // Build the ring buffer in current thread
        let rb = rb_builder.build()
            .context("Failed to build ring buffer")?;
        
        // Start the synchronous ring buffer polling in a dedicated thread
        let poll_shutdown = Arc::clone(&shutdown);
        let poll_config = config.clone();
        
        std::thread::spawn(move || {
            Self::ring_buffer_poll_thread_with_rb(
                rb,
                poll_shutdown,
                poll_config,
            );
        });

        // Start the async event processing pipeline
        tokio::spawn(Self::async_event_processor(
            raw_event_rx,
            sender,
            metrics,
            rate_limiter,
            shutdown,
            config,
        ));

        info!("📡 High-performance ring buffer processor setup completed");
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn ring_buffer_poll_thread_with_rb(
        rb: libbpf_rs::RingBuffer,
        shutdown: Arc<tokio::sync::Notify>,
        config: EbpfConfig,
    ) {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc as StdArc;
        
        info!("🔄 Starting dedicated high-performance ring buffer polling thread");
        
        let shutdown_flag = StdArc::new(AtomicBool::new(false));
        let shutdown_flag_clone = StdArc::clone(&shutdown_flag);
        
        // Spawn a thread to watch for shutdown signal
        std::thread::spawn(move || {
            match tokio::runtime::Runtime::new() {
                Ok(rt) => {
                    rt.block_on(async {
                        shutdown.notified().await;
                        shutdown_flag_clone.store(true, Ordering::SeqCst);
                    });
                }
                Err(e) => {
                    error!("Failed to create tokio runtime for shutdown handler: {}", e);
                    // Force shutdown flag to avoid hanging
                    shutdown_flag_clone.store(true, Ordering::SeqCst);
                }
            }
        });

        info!("🚀 Ring buffer polling thread active with optimized settings");

        // High-frequency polling loop with microsecond precision
        let poll_timeout = Duration::from_micros(config.ring_buffer_poll_timeout_us.unwrap_or(100));
        let mut poll_count = 0u64;
        let mut last_stats = std::time::Instant::now();
        
        while !shutdown_flag.load(Ordering::SeqCst) {
            match rb.poll(poll_timeout) {
                Ok(_) => {
                    // Events processed through callback
                    poll_count += 1;
                    
                    // Log performance stats every 10 seconds
                    if poll_count % 100000 == 0 {
                        let now = std::time::Instant::now();
                        let duration = now.duration_since(last_stats);
                        if duration.as_secs() >= 10 {
                            let polls_per_sec = 100000.0 / duration.as_secs_f64();
                            debug!("Ring buffer performance: {:.0} polls/sec", polls_per_sec);
                            last_stats = now;
                        }
                    }
                }
                Err(e) => {
                    error!("Ring buffer poll error: {}", e);
                    if config.auto_recovery {
                        std::thread::sleep(Duration::from_millis(10));
                        continue;
                    } else {
                        break;
                    }
                }
            }
        }

        info!("🛑 Ring buffer polling thread stopped (processed {} polls)", poll_count);
    }

    #[cfg(target_os = "linux")]
    async fn async_event_processor(
        mut raw_event_rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
        sender: mpsc::Sender<RawEvent>,
        metrics: Arc<RwLock<EbpfMetrics>>,
        rate_limiter: Arc<Semaphore>,
        shutdown: Arc<tokio::sync::Notify>,
        config: EbpfConfig,
    ) {
        info!("⚡ Starting high-performance async event processor");

        // Batch processing for higher throughput
        let mut event_batch = Vec::with_capacity(config.batch_size.unwrap_or(64));
        let batch_timeout = Duration::from_micros(config.batch_timeout_us.unwrap_or(1000));
        let mut batch_timer = tokio::time::interval(batch_timeout);
        
        loop {
            tokio::select! {
                // Process incoming raw events
                Some(raw_data) = raw_event_rx.recv() => {
                    event_batch.push(raw_data);
                    
                    // Process batch when it's full
                    if event_batch.len() >= event_batch.capacity() {
                        Self::process_event_batch(
                            &mut event_batch,
                            &sender,
                            &metrics,
                            &rate_limiter,
                        ).await;
                    }
                }
                
                // Process batch on timeout (ensure low latency)
                _ = batch_timer.tick() => {
                    if !event_batch.is_empty() {
                        Self::process_event_batch(
                            &mut event_batch,
                            &sender,
                            &metrics,
                            &rate_limiter,
                        ).await;
                    }
                }
                
                // Handle shutdown
                _ = shutdown.notified() => {
                    info!("Processing remaining events before shutdown...");
                    // Process any remaining events
                    if !event_batch.is_empty() {
                        Self::process_event_batch(
                            &mut event_batch,
                            &sender,
                            &metrics,
                            &rate_limiter,
                        ).await;
                    }
                    break;
                }
            }
        }

        info!("⚡ Async event processor stopped");
    }

    #[cfg(target_os = "linux")]
    async fn process_event_batch(
        event_batch: &mut Vec<Vec<u8>>,
        sender: &mpsc::Sender<RawEvent>,
        metrics: &Arc<RwLock<EbpfMetrics>>,
        rate_limiter: &Arc<Semaphore>,
    ) {
        let batch_size = event_batch.len();
        let mut processed = 0;
        let mut dropped = 0;
        let mut errors = 0;

        for raw_data in event_batch.drain(..) {
            // Rate limiting check
            if rate_limiter.try_acquire().is_err() {
                dropped += 1;
                continue;
            }

            // Parse event
            match Self::parse_event_sync(&raw_data) {
                Ok(event) => {
                    // Try to send event
                    if sender.try_send(event).is_ok() {
                        processed += 1;
                    } else {
                        dropped += 1;
                    }
                }
                Err(_) => {
                    errors += 1;
                }
            }
        }

        // Update metrics efficiently
        {
            let mut metrics_guard = metrics.write().await;
            metrics_guard.events_processed += processed;
            metrics_guard.events_dropped += dropped;
            metrics_guard.processing_errors += errors;
            metrics_guard.last_event_timestamp = Some(Instant::now());
        }

        if batch_size > 0 {
            debug!("Processed batch: {} events, {} processed, {} dropped, {} errors", 
                   batch_size, processed, dropped, errors);
        }
    }

    async fn start_background_tasks(&self) -> Result<()> {
        // Start heartbeat task
        let heartbeat_task = Self::heartbeat_task(
            self.event_sender.clone(),
            Arc::clone(&self.metrics),
            Arc::clone(&self.shutdown_signal),
            self.config.metrics_interval_sec,
        );
        tokio::spawn(heartbeat_task);

        // Start metrics collection task
        let metrics_task = Self::metrics_collector_task(
            Arc::clone(&self.metrics),
            Arc::clone(&self.shutdown_signal),
        );
        tokio::spawn(metrics_task);

        info!("🚀 Background async tasks started");
        Ok(())
    }

    async fn heartbeat_task(
        sender: mpsc::Sender<RawEvent>,
        metrics: Arc<RwLock<EbpfMetrics>>,
        shutdown: Arc<tokio::sync::Notify>,
        interval_sec: u64,
    ) {
        let mut interval = interval(Duration::from_secs(interval_sec));
        let mut sequence = 0u64;

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    sequence += 1;
                    let metrics_snapshot = metrics.read().await.clone();
                    
                    let heartbeat_event = RawEvent::Heartbeat(HeartbeatEvent {
                        timestamp: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64,
                        sequence,
                        metrics: metrics_snapshot,
                    });

                    if let Err(_) = sender.send(heartbeat_event).await {
                        debug!("Heartbeat event send failed, channel may be full");
                        break;
                    }
                }
                _ = shutdown.notified() => {
                    debug!("Heartbeat task received shutdown signal");
                    break;
                }
            }
        }
    }

    async fn metrics_collector_task(
        metrics: Arc<RwLock<EbpfMetrics>>,
        shutdown: Arc<tokio::sync::Notify>,
    ) {
        let mut interval = interval(Duration::from_secs(60));
        
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let mut metrics_guard = metrics.write().await;
                    metrics_guard.uptime_seconds += 60;
                    
                    // Calculate peak events per second
                    if let Some(last_timestamp) = metrics_guard.last_event_timestamp {
                        let elapsed = last_timestamp.elapsed().as_secs();
                        if elapsed > 0 {
                            let current_eps = metrics_guard.events_processed / elapsed;
                            metrics_guard.peak_events_per_sec = metrics_guard.peak_events_per_sec.max(current_eps);
                        }
                    }
                }
                _ = shutdown.notified() => {
                    debug!("Metrics collection task received shutdown signal");
                    break;
                }
            }
        }
    }

    async fn start_mock_mode(&self) -> Result<()> {
        let sender = self.event_sender.clone();
        let metrics = Arc::clone(&self.metrics);
        let shutdown = Arc::clone(&self.shutdown_signal);

        // Start general background tasks
        self.start_background_tasks().await?;

        // Start mock event generator
        tokio::spawn(Self::mock_event_generator(sender, metrics, shutdown));

        Ok(())
    }

    async fn mock_event_generator(
        sender: mpsc::Sender<RawEvent>,
        metrics: Arc<RwLock<EbpfMetrics>>,
        shutdown: Arc<tokio::sync::Notify>,
    ) {
        info!("🎭 Mock event generator started");
        
        let mut interval = interval(Duration::from_millis(200));
        
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let mock_event = Self::generate_mock_event().await;
                    
                    if let Err(_) = sender.send(mock_event).await {
                        break;
                    }
                    
                    // Update metrics
                    let mut metrics_guard = metrics.write().await;
                    metrics_guard.events_processed += 1;
                    metrics_guard.last_event_timestamp = Some(Instant::now());
                    
                    // Randomly adjust interval
                    let jitter = Duration::from_millis(fastrand::u64(50..500));
                    interval = tokio::time::interval(jitter);
                }
                _ = shutdown.notified() => {
                    debug!("Mock event generator received shutdown signal");
                    break;
                }
            }
        }
    }

    async fn generate_mock_event() -> RawEvent {
        let event_type = fastrand::u32(0..3);
        let timestamp = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64;
        
        match event_type {
            0 => {
                // Mock process execution event
                let processes = ["bash", "python3", "curl", "wget", "ssh", "vim", "ls", "ps"];
                let process = processes[fastrand::usize(..processes.len())];
                
                let mut comm = [0u8; 16];
                let process_bytes = process.as_bytes();
                let copy_len = process_bytes.len().min(15);
                comm[..copy_len].copy_from_slice(&process_bytes[..copy_len]);
                
                let filenames = [
                    "/bin/bash", "/usr/bin/python3", "/usr/bin/curl", 
                    "/usr/bin/wget", "/usr/bin/ssh", "/usr/bin/vim"
                ];
                let filename = filenames[fastrand::usize(..filenames.len())];
                
                let mut filename_bytes = [0u8; 256];
                let filename_str = filename.as_bytes();
                let copy_len = filename_str.len().min(255);
                filename_bytes[..copy_len].copy_from_slice(&filename_str[..copy_len]);
                
                RawEvent::Exec(ExecEvent {
                    timestamp,
                    pid: fastrand::u32(1000..9999),
                    ppid: fastrand::u32(1..1000),
                    uid: fastrand::u32(1000..2000),
                    gid: fastrand::u32(1000..2000),
                    comm,
                    filename: filename_bytes,
                    args_count: fastrand::u8(1..5),
                    exit_code: 0,
                })
            }
            1 => {
                // Mock network connection event
                let mut comm = [0u8; 16];
                let process = "curl";
                let process_bytes = process.as_bytes();
                comm[..process_bytes.len()].copy_from_slice(process_bytes);
                
                RawEvent::NetConn(NetConnEvent {
                    timestamp,
                    pid: fastrand::u32(1000..9999),
                    uid: fastrand::u32(1000..2000),
                    comm,
                    saddr: 0x0100007f, // 127.0.0.1
                    daddr: 0x08080808, // 8.8.8.8
                    sport: fastrand::u16(1024..65535),
                    dport: fastrand::u16(80..8080),
                    protocol: 6, // TCP
                    direction: 0, // outbound
                })
            }
            _ => {
                // Mock file operation event
                let mut comm = [0u8; 16];
                let process = "vim";
                let process_bytes = process.as_bytes();
                comm[..process_bytes.len()].copy_from_slice(process_bytes);
                
                let files = [
                    "/tmp/test.txt", "/home/user/document.txt", 
                    "/var/log/system.log", "/etc/config.conf"
                ];
                let file = files[fastrand::usize(..files.len())];
                
                let mut filename_bytes = [0u8; 256];
                let file_str = file.as_bytes();
                let copy_len = file_str.len().min(255);
                filename_bytes[..copy_len].copy_from_slice(&file_str[..copy_len]);
                
                RawEvent::FileOp(FileOpEvent {
                    timestamp,
                    pid: fastrand::u32(1000..9999),
                    uid: fastrand::u32(1000..2000),
                    comm,
                    operation: 2, // open
                    filename: filename_bytes,
                    mode: 0o644,
                    size: fastrand::u64(100..10000),
                    flags: 0,
                })
            }
        }
    }

    pub async fn event_stream(&self) -> impl Stream<Item = RawEvent> {
        let receiver = {
            let mut receiver_guard = self.event_receiver.write().await;
            receiver_guard.take().expect("Event receiver can only be obtained once")
        };
        
        ReceiverStream::new(receiver)
    }

    pub async fn next_event_timeout(&self, timeout_duration: Duration) -> Result<Option<RawEvent>> {
        let mut stream = self.event_stream().await;
        
        match timeout(timeout_duration, stream.next()).await {
            Ok(Some(event)) => Ok(Some(event)),
            Ok(None) => Ok(None),
            Err(_) => Ok(None), // Timeout
        }
    }

    pub async fn collect_events_batch(&self, batch_size: usize, max_wait: Duration) -> Vec<RawEvent> {
        let mut events = Vec::new();
        let mut stream = self.event_stream().await;
        let start_time = Instant::now();
        
        while events.len() < batch_size && start_time.elapsed() < max_wait {
            match timeout(Duration::from_millis(100), stream.next()).await {
                Ok(Some(event)) => events.push(event),
                Ok(None) => break,
                Err(_) => break,
            }
        }
        
        events
    }

    pub async fn get_metrics(&self) -> EbpfMetrics {
        self.metrics.read().await.clone()
    }

    pub async fn reset_metrics(&self) {
        let mut metrics = self.metrics.write().await;
        *metrics = EbpfMetrics::default();
    }

    pub async fn shutdown(&self) {
        info!("🛑 Shutting down eBPF loader...");
        self.shutdown_signal.notify_waiters();
    }

    #[cfg(target_os = "linux")]
    pub fn parse_event_sync(data: &[u8]) -> Result<RawEvent> {
        if data.len() < 8 {
            return Err(SentinelError::Parse(format!(
                "Event data too short: expected at least 8 bytes, got {}", data.len()
            )));
        }

        // Simple event type detection based on data size
        match data.len() {
            size if size >= std::mem::size_of::<ExecEvent>() => {
                // Try to parse as ExecEvent
                let exec_event = unsafe { std::ptr::read(data.as_ptr() as *const ExecEvent) };
                Ok(RawEvent::Exec(exec_event))
            }
            size if size >= std::mem::size_of::<NetConnEvent>() => {
                // Try to parse as NetConnEvent
                let net_event = unsafe { std::ptr::read(data.as_ptr() as *const NetConnEvent) };
                Ok(RawEvent::NetConn(net_event))
            }
            size if size >= std::mem::size_of::<FileOpEvent>() => {
                // Try to parse as FileOpEvent
                let file_event = unsafe { std::ptr::read(data.as_ptr() as *const FileOpEvent) };
                Ok(RawEvent::FileOp(file_event))
            }
            _ => {
                // Create error event
                Ok(RawEvent::Error(EventError {
                    timestamp: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64,
                    error_type: ErrorType::ParseError,
                    message: "Unknown event type".to_string(),
                    context: "parse_event_sync".to_string(),
                }))
            }
        }
    }

    pub fn is_real_mode(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            self._object.is_some()
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }
}

// Helper function: Convert C string to Rust string
pub fn c_str_to_string(c_str: &[u8]) -> String {
    let null_pos = c_str.iter().position(|&x| x == 0).unwrap_or(c_str.len());
    String::from_utf8_lossy(&c_str[..null_pos]).to_string()
}

// Helper function: Convert IP address to string
pub fn ip_to_string(ip: u32) -> String {
    format!("{}.{}.{}.{}", 
        (ip >> 24) & 0xFF,
        (ip >> 16) & 0xFF, 
        (ip >> 8) & 0xFF,
        ip & 0xFF
    )
}

 