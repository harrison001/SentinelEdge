// kernel-agent/src/lib.rs
// Event definitions and data structures

use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock, Semaphore};
use tokio::time::{interval, timeout, Instant};
use tokio_stream::{wrappers::ReceiverStream, Stream, StreamExt};
use tracing::{debug, info, warn, instrument};

#[cfg(target_os = "linux")]
use anyhow::Context;
#[cfg(target_os = "linux")]
use tracing::error;
#[cfg(target_os = "linux")]
use libbpf_rs::{RingBufferBuilder, Object, ObjectBuilder, RingBuffer};

pub mod events;

pub use events::*;

pub struct EbpfLoader {
    config: EbpfConfig,
    event_sender: mpsc::Sender<RawEvent>,
    event_receiver: Arc<RwLock<Option<mpsc::Receiver<RawEvent>>>>,
    metrics: Arc<RwLock<EbpfMetrics>>,
    shutdown_signal: Arc<tokio::sync::Notify>,
    rate_limiter: Arc<Semaphore>,
    #[cfg(target_os = "linux")]
    _object: Option<Object>,
}

#[derive(Debug, Clone)]
pub struct EbpfConfig {
    pub ring_buffer_size: usize,
    pub event_batch_size: usize,
    pub poll_timeout_ms: u64,
    pub max_events_per_sec: usize,
    pub enable_backpressure: bool,
    pub auto_recovery: bool,
    pub metrics_interval_sec: u64,
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
        }
    }
}

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

#[derive(Debug, Clone)]
pub enum RawEvent {
    Exec(ExecEvent),
    NetConn(NetConnEvent),
    FileOp(FileOpEvent),
    Error(EventError),
    Heartbeat(HeartbeatEvent),
}

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
    pub fn new() -> Self {
        Self::with_config(EbpfConfig::default())
    }

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

    #[instrument(skip(self))]
    pub async fn initialize(&mut self) -> Result<()> {
        info!("🔧 Initializing high-performance async eBPF loader...");

        #[cfg(target_os = "linux")]
        {
            if !nix::unistd::Uid::effective().is_root() {
                return Err(anyhow::anyhow!("Root privileges required to load eBPF programs"));
            }

            match self.initialize_linux().await {
                Ok(object) => {
                    info!("✅ eBPF program loaded successfully, starting async event processing");
                    self._object = Some(object);
                    
                    // Start async tasks
                    self.start_background_tasks().await?;
                }
                Err(e) => {
                    warn!("⚠️  eBPF program loading failed: {}", e);
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
        let object = ObjectBuilder::default()
            .open_file("kernel-agent/src/sentinel.bpf.o")
            .context("Cannot open eBPF object file")?
            .load()
            .context("Cannot load eBPF program")?;

        object.attach().context("Cannot attach eBPF program to kernel")?;

        let rb_map = object
            .map("events")
            .context("Cannot find ring buffer map")?;

        // Create async ring buffer processor
        let sender = self.event_sender.clone();
        let metrics = Arc::clone(&self.metrics);
        let rate_limiter = Arc::clone(&self.rate_limiter);
        let shutdown = Arc::clone(&self.shutdown_signal);
        let config = self.config.clone();

        tokio::spawn(Self::ring_buffer_processor(
            rb_map,
            sender,
            metrics,
            rate_limiter,
            shutdown,
            config,
        ));

        Ok(object)
    }

    #[cfg(target_os = "linux")]
    async fn ring_buffer_processor(
        rb_map: libbpf_rs::Map,
        sender: mpsc::Sender<RawEvent>,
        metrics: Arc<RwLock<EbpfMetrics>>,
        rate_limiter: Arc<Semaphore>,
        shutdown: Arc<tokio::sync::Notify>,
        config: EbpfConfig,
    ) {
        let mut rb_builder = RingBufferBuilder::new();
        
        rb_builder.add(&rb_map, move |data: &[u8]| {
            let sender = sender.clone();
            let metrics = Arc::clone(&metrics);
            let rate_limiter = Arc::clone(&rate_limiter);
            
            // Rate limiting
            if let Err(_) = rate_limiter.try_acquire() {
                tokio::spawn(async move {
                    let mut metrics_guard = metrics.write().await;
                    metrics_guard.events_dropped += 1;
                });
                return 0;
            }

            // Parse event
            match Self::parse_event_sync(data) {
                Ok(event) => {
                    tokio::spawn(async move {
                        if let Err(_) = sender.send(event).await {
                            // Channel full, update metrics
                            let mut metrics_guard = metrics.write().await;
                            metrics_guard.events_dropped += 1;
                        } else {
                            let mut metrics_guard = metrics.write().await;
                            metrics_guard.events_processed += 1;
                            metrics_guard.last_event_timestamp = Some(Instant::now());
                        }
                    });
                }
                Err(e) => {
                    tokio::spawn(async move {
                        let mut metrics_guard = metrics.write().await;
                        metrics_guard.processing_errors += 1;
                        debug!("Event parsing error: {}", e);
                    });
                }
            }
            0
        });

        let mut rb = match rb_builder.build() {
            Ok(rb) => rb,
            Err(e) => {
                error!("Cannot create ring buffer: {}", e);
                return;
            }
        };

        info!("📡 Async ring buffer processor started");

        let mut poll_interval = interval(Duration::from_millis(config.poll_timeout_ms));

        loop {
            tokio::select! {
                _ = poll_interval.tick() => {
                    // Use spawn_blocking to handle the synchronous poll operation
                    // We need to use a different approach since RingBuffer doesn't support clone
                    match tokio::task::spawn_blocking({
                        // Move ownership temporarily using Option
                        let timeout = Duration::from_millis(config.poll_timeout_ms);
                        move || {
                            // This is a workaround - we need to restructure to avoid cloning
                            // For now, we'll use a shorter timeout in a different way
                            std::thread::sleep(Duration::from_millis(10));
                            Ok::<(), anyhow::Error>(())
                        }
                    }).await {
                        Ok(Ok(())) => {
                            // Poll the ring buffer directly without clone
                            if let Err(e) = rb.poll(Duration::from_millis(1)) {
                                error!("Ring buffer polling error: {}", e);
                                if config.auto_recovery {
                                    warn!("Attempting auto recovery...");
                                    tokio::time::sleep(Duration::from_secs(1)).await;
                                    continue;
                                }
                                break;
                            }
                        }
                        Ok(Err(e)) => {
                            error!("Ring buffer polling error: {}", e);
                            if config.auto_recovery {
                                warn!("Attempting auto recovery...");
                                tokio::time::sleep(Duration::from_secs(1)).await;
                                continue;
                            }
                            break;
                        }
                        Err(e) => {
                            error!("Ring buffer task error: {}", e);
                            break;
                        }
                    }
                }
                _ = shutdown.notified() => {
                    info!("Received shutdown signal, stopping ring buffer processor");
                    break;
                }
            }
        }

        info!("Ring buffer processor stopped");
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
    fn parse_event_sync(data: &[u8]) -> Result<RawEvent> {
        if data.len() < 8 {
            return Err(anyhow::anyhow!("Event data too short"));
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
                    timestamp: chrono::Utc::now().timestamp_nanos() as u64,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ebpf_loader_initialization() {
        let mut loader = EbpfLoader::new();
        let result = loader.initialize().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_event_stream() {
        let mut loader = EbpfLoader::new();
        loader.initialize().await.unwrap();
        
        let mut stream = loader.event_stream().await;
        
        // Should receive events (mock mode)
        tokio::time::timeout(Duration::from_secs(3), stream.next()).await.unwrap();
    }

    #[tokio::test]
    async fn test_metrics_collection() {
        let mut loader = EbpfLoader::new();
        loader.initialize().await.unwrap();
        
        tokio::time::sleep(Duration::from_secs(1)).await;
        
        let metrics = loader.get_metrics().await;
        assert!(metrics.uptime_seconds > 0);
    }
} 