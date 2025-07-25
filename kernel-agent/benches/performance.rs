use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use kernel_agent::*;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock, Semaphore};
use libc::{getpid, getuid};

/// Create production-grade benchmark configuration
fn create_benchmark_config() -> EbpfConfig {
    EbpfConfig {
        ring_buffer_size: 2 * 1024 * 1024,  // 2MB - production size
        event_batch_size: 256,               // Larger batches for better performance
        poll_timeout_ms: 1,
        max_events_per_sec: 100000,
        enable_backpressure: true,
        auto_recovery: true,
        metrics_interval_sec: 10,
        // High-performance optimizations based on real systems
        ring_buffer_poll_timeout_us: Some(5),    // 5 microseconds - aggressive polling
        batch_size: Some(256),                   // Large batches
        batch_timeout_us: Some(50),              // 50μs timeout
    }
}

/// Create realistic event data based on actual Linux system events
fn create_benchmark_event(id: u32) -> Vec<u8> {
    let mut event_data = Vec::with_capacity(400);
    
    // Real timestamp from system clock
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    event_data.extend_from_slice(&timestamp.to_le_bytes());
    
    // Realistic PID based on current process
    let base_pid = unsafe { getpid() } as u32;
    let pid = base_pid.wrapping_add(id % 10000);  // Wider PID range
    event_data.extend_from_slice(&pid.to_le_bytes());
    
    // Realistic PPID
    let ppid = if id % 10 == 0 { 1 } else { base_pid };  // Some processes have init as parent
    event_data.extend_from_slice(&ppid.to_le_bytes());
    
    // Real UID/GID from system
    let uid = unsafe { getuid() };
    let gid = uid;  // Typically same as UID
    event_data.extend_from_slice(&uid.to_le_bytes());
    event_data.extend_from_slice(&gid.to_le_bytes());
    
    // Realistic command names from actual Linux systems
    let realistic_commands = [
        "systemd", "kthreadd", "ksoftirqd", "migration", "rcu_gp", "rcu_par_gp",
        "kworker", "mm_percpu_wq", "oom_reaper", "writeback", "kcompactd0",
        "kintegrityd", "kblockd", "tpm_dev_wq", "ata_sff", "md", "edac-poller",
        "devfreq_wq", "watchdog", "NetworkManager", "systemd-resolved",
        "systemd-timesyncd", "cron", "dbus-daemon", "rsyslog", "sshd",
        "irqbalance", "thermald", "acpid", "snapd", "accounts-daemon"
    ];
    let mut comm = [0u8; 16];
    let comm_str = realistic_commands[id as usize % realistic_commands.len()];
    let bytes = comm_str.as_bytes();
    let len = std::cmp::min(bytes.len(), 15);
    comm[..len].copy_from_slice(&bytes[..len]);
    event_data.extend_from_slice(&comm);
    
    // Realistic file paths from real Linux filesystem
    let realistic_paths = [
        "/lib/systemd/systemd", "/usr/bin/kthreadd", "/proc/sys/kernel/random/boot_id",
        "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor", "/var/log/syslog",
        "/etc/passwd", "/etc/hosts", "/proc/meminfo", "/proc/loadavg", "/proc/stat",
        "/sys/class/net/eth0/statistics/rx_bytes", "/run/systemd/resolve/stub-resolv.conf",
        "/var/lib/systemd/random-seed", "/etc/machine-id", "/proc/version",
        "/sys/fs/cgroup/memory/memory.usage_in_bytes", "/dev/urandom", "/etc/localtime",
        "/usr/lib/x86_64-linux-gnu/libc.so.6", "/lib/x86_64-linux-gnu/libpthread.so.0",
        "/sys/devices/virtual/block/loop0/stat", "/proc/1/status", "/proc/interrupts",
        "/sys/kernel/debug/tracing/trace_pipe", "/dev/null", "/tmp/systemd-private-"
    ];
    let mut filename = [0u8; 256];
    let filename_str = realistic_paths[id as usize % realistic_paths.len()];
    let bytes = filename_str.as_bytes();
    let len = std::cmp::min(bytes.len(), 255);
    filename[..len].copy_from_slice(&bytes[..len]);
    event_data.extend_from_slice(&filename);
    
    // Realistic args count (0-4, with most processes having 0-2 args)
    let args_count = match id % 10 {
        0..=5 => 0,   // 60% have no args
        6..=8 => 1,   // 30% have 1 arg
        _ => 2,       // 10% have 2+ args
    };
    event_data.push(args_count);
    
    // Realistic exit codes (mostly 0, occasional failures)
    let exit_code = if id % 100 == 0 { -1i32 } else { 0i32 };
    event_data.extend_from_slice(&exit_code.to_le_bytes());
    
    event_data
}

/// 基准测试：事件解析性能
fn bench_event_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("event_parsing");
    
    for event_count in [100, 1000, 10000].iter() {
        let events: Vec<Vec<u8>> = (0..*event_count)
            .map(|i| create_benchmark_event(i))
            .collect();
        
        group.bench_with_input(
            BenchmarkId::new("parse_events", event_count),
            event_count,
            |b, _| {
                b.iter(|| {
                    for event_data in &events {
                        let _ = black_box(EbpfLoader::parse_event_sync(event_data));
                    }
                });
            },
        );
    }
    
    group.finish();
}

/// 基准测试：批处理性能
fn bench_batch_processing(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("batch_processing");
    group.measurement_time(Duration::from_secs(10));
    
    for batch_size in [16, 64, 256].iter() {
        group.bench_with_input(
            BenchmarkId::new("process_batch", batch_size),
            batch_size,
            |b, &size| {
                b.to_async(&rt).iter(|| async {
                    let config = create_benchmark_config();
                    let (sender, _receiver) = mpsc::channel(1000);
                    let metrics = Arc::new(RwLock::new(EbpfMetrics::default()));
                    let rate_limiter = Arc::new(Semaphore::new(100000));
                    
                    let mut event_batch: Vec<Vec<u8>> = (0..size)
                        .map(|i| create_benchmark_event(i))
                        .collect();
                    
                    EbpfLoader::process_event_batch(
                        &mut event_batch,
                        &sender,
                        &metrics,
                        &rate_limiter,
                    ).await;
                });
            },
        );
    }
    
    group.finish();
}

/// 基准测试：高并发处理
fn bench_concurrent_processing(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("concurrent_processing");
    group.measurement_time(Duration::from_secs(15));
    
    for thread_count in [1, 4, 8, 16].iter() {
        group.bench_with_input(
            BenchmarkId::new("concurrent_tasks", thread_count),
            thread_count,
            |b, &threads| {
                b.to_async(&rt).iter(|| async {
                    let config = create_benchmark_config();
                    let loader = EbpfLoader::with_config(config);
                    
                    let mut tasks = Vec::new();
                    let events_per_thread = 1000;
                    
                    for thread_id in 0..threads {
                        let sender = loader.event_sender.clone();
                        
                        let task = tokio::spawn(async move {
                            for i in 0..events_per_thread {
                                let event_data = create_benchmark_event(thread_id * events_per_thread + i);
                                if let Ok(event) = EbpfLoader::parse_event_sync(&event_data) {
                                    let _ = sender.try_send(event);
                                }
                            }
                        });
                        
                        tasks.push(task);
                    }
                    
                    // Wait for all tasks
                    for task in tasks {
                        let _ = task.await;
                    }
                });
            },
        );
    }
    
    group.finish();
}

/// 基准测试：内存分配性能
fn bench_memory_allocation(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_allocation");
    
    group.bench_function("event_creation", |b| {
        b.iter(|| {
            let events: Vec<Vec<u8>> = (0..1000)
                .map(|i| black_box(create_benchmark_event(i)))
                .collect();
            black_box(events);
        });
    });
    
    group.bench_function("config_creation", |b| {
        b.iter(|| {
            let config = black_box(create_benchmark_config());
            let loader = black_box(EbpfLoader::with_config(config));
            black_box(loader);
        });
    });
    
    group.finish();
}

/// Benchmark: End-to-end latency with realistic conditions
fn bench_end_to_end_latency(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("end_to_end_latency");
    group.measurement_time(Duration::from_secs(15));
    
    group.bench_function("single_event_latency", |b| {
        b.to_async(&rt).iter(|| async {
            let config = create_benchmark_config();
            let (raw_tx, raw_rx) = tokio::sync::mpsc::unbounded_channel();
            let (processed_tx, mut processed_rx) = mpsc::channel(1000);
            
            let metrics = Arc::new(RwLock::new(EbpfMetrics::default()));
            let rate_limiter = Arc::new(Semaphore::new(100000));
            let shutdown = Arc::new(tokio::sync::Notify::new());
            
            // Start processor
            let processor_shutdown = shutdown.clone();
            let _processor = tokio::spawn(EbpfLoader::async_event_processor(
                raw_rx,
                processed_tx,
                metrics,
                rate_limiter,
                processor_shutdown,
                config,
            ));
            
            // Send realistic event and measure latency
            let start = std::time::Instant::now();
            let event_data = create_benchmark_event(42);
            raw_tx.send(event_data).unwrap();
            
            // Wait for processed event
            if let Ok(_event) = tokio::time::timeout(Duration::from_millis(50), processed_rx.recv()).await {
                let _latency = start.elapsed();
            }
            
            shutdown.notify_one();
        });
    });
    
    // Add realistic system load simulation
    group.bench_function("latency_under_load", |b| {
        b.to_async(&rt).iter(|| async {
            let config = create_benchmark_config();
            let (raw_tx, raw_rx) = tokio::sync::mpsc::unbounded_channel();
            let (processed_tx, mut processed_rx) = mpsc::channel(10000);
            
            let metrics = Arc::new(RwLock::new(EbpfMetrics::default()));
            let rate_limiter = Arc::new(Semaphore::new(100000));
            let shutdown = Arc::new(tokio::sync::Notify::new());
            
            let processor_shutdown = shutdown.clone();
            let _processor = tokio::spawn(EbpfLoader::async_event_processor(
                raw_rx,
                processed_tx,
                metrics,
                rate_limiter,
                processor_shutdown,
                config,
            ));
            
            // Create background load
            let background_tx = raw_tx.clone();
            let _background_load = tokio::spawn(async move {
                for i in 0..100 {
                    let event_data = create_benchmark_event(i);
                    let _ = background_tx.send(event_data);
                    if i % 10 == 0 {
                        tokio::task::yield_now().await;
                    }
                }
            });
            
            // Measure target event latency under load
            let start = std::time::Instant::now();
            let event_data = create_benchmark_event(999);
            raw_tx.send(event_data).unwrap();
            
            // Wait for processed events (drain some)
            for _ in 0..10 {
                if tokio::time::timeout(Duration::from_millis(10), processed_rx.recv()).await.is_err() {
                    break;
                }
            }
            
            let _latency_under_load = start.elapsed();
            shutdown.notify_one();
        });
    });
    
    group.finish();
}

/// Benchmark: Realistic system stress scenarios
fn bench_realistic_system_stress(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("realistic_system_stress");
    group.measurement_time(Duration::from_secs(20));
    
    // Simulate file system burst activity
    group.bench_function("filesystem_burst", |b| {
        b.to_async(&rt).iter(|| async {
            let config = create_benchmark_config();
            let loader = EbpfLoader::with_config(config);
            
            // Simulate file system events burst (common in real systems)
            let file_events = [
                ("systemd", "/var/log/syslog"),
                ("rsyslog", "/var/log/auth.log"),
                ("logrotate", "/var/log/syslog.1"),
                ("cron", "/var/spool/cron/crontabs/root"),
                ("systemd", "/run/systemd/units/invocation:cron.service"),
            ];
            
            for (i, (comm, path)) in file_events.iter().cycle().take(200).enumerate() {
                let event_data = create_realistic_fs_event(i as u32, comm, path);
                if let Ok(event) = EbpfLoader::parse_event_sync(&event_data) {
                    let _ = loader.event_sender.try_send(event);
                }
                
                if i % 20 == 0 {
                    tokio::task::yield_now().await;
                }
            }
        });
    });
    
    // Simulate network activity spike
    group.bench_function("network_activity_spike", |b| {
        b.to_async(&rt).iter(|| async {
            let config = create_benchmark_config();
            let loader = EbpfLoader::with_config(config);
            
            // Simulate network events (SSH connections, HTTP requests, etc.)
            let network_events = [
                ("sshd", "/proc/net/tcp"),
                ("NetworkManager", "/proc/net/route"),
                ("systemd-resolved", "/run/systemd/resolve/stub-resolv.conf"),
                ("curl", "/etc/ssl/certs/ca-certificates.crt"),
                ("wget", "/tmp/download.tmp"),
            ];
            
            for (i, (comm, path)) in network_events.iter().cycle().take(150).enumerate() {
                let event_data = create_realistic_network_event(i as u32, comm, path);
                if let Ok(event) = EbpfLoader::parse_event_sync(&event_data) {
                    let _ = loader.event_sender.try_send(event);
                }
                
                if i % 15 == 0 {
                   tokio::task::yield_now().await;
                }
            }
        });
    });
    
    // Simulate process creation storm
    group.bench_function("process_creation_storm", |b| {
        b.to_async(&rt).iter(|| async {
            let config = create_benchmark_config();
            let loader = EbpfLoader::with_config(config);
            
            // Simulate process creation events (shell scripts, system startup, etc.)
            let process_chains = [
                ("bash", "/bin/bash"),
                ("sh", "/bin/sh"),
                ("grep", "/bin/grep"),
                ("awk", "/usr/bin/awk"),
                ("sed", "/bin/sed"),
                ("sort", "/usr/bin/sort"),
                ("uniq", "/usr/bin/uniq"),
                ("cat", "/bin/cat"),
            ];
            
            for (i, (comm, path)) in process_chains.iter().cycle().take(300).enumerate() {
                let event_data = create_realistic_process_event(i as u32, comm, path);
                if let Ok(event) = EbpfLoader::parse_event_sync(&event_data) {
                    let _ = loader.event_sender.try_send(event);
                }
                
                if i % 25 == 0 {
                    tokio::task::yield_now().await;
                }
            }
        });
    });
    
    group.finish();
}

/// Create realistic file system event
fn create_realistic_fs_event(id: u32, comm: &str, filepath: &str) -> Vec<u8> {
    let mut event_data = Vec::with_capacity(400);
    
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    event_data.extend_from_slice(&timestamp.to_le_bytes());
    
    let base_pid = unsafe { getpid() } as u32;
    event_data.extend_from_slice(&(base_pid + id).to_le_bytes());
    event_data.extend_from_slice(&base_pid.to_le_bytes());
    
    let uid = unsafe { getuid() };
    event_data.extend_from_slice(&uid.to_le_bytes());
    event_data.extend_from_slice(&uid.to_le_bytes());
    
    let mut comm_bytes = [0u8; 16];
    let comm_data = comm.as_bytes();
    let len = std::cmp::min(comm_data.len(), 15);
    comm_bytes[..len].copy_from_slice(&comm_data[..len]);
    event_data.extend_from_slice(&comm_bytes);
    
    let mut filename_bytes = [0u8; 256];
    let filename_data = filepath.as_bytes();
    let len = std::cmp::min(filename_data.len(), 255);
    filename_bytes[..len].copy_from_slice(&filename_data[..len]);
    event_data.extend_from_slice(&filename_bytes);
    
    event_data.push(if id % 5 == 0 { 1 } else { 0 });
    event_data.extend_from_slice(&0i32.to_le_bytes());
    
    event_data
}

/// Create realistic network event
fn create_realistic_network_event(id: u32, comm: &str, filepath: &str) -> Vec<u8> {
    let mut event_data = Vec::with_capacity(400);
    
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    event_data.extend_from_slice(&timestamp.to_le_bytes());
    
    let base_pid = unsafe { getpid() } as u32;
    event_data.extend_from_slice(&(base_pid + id + 2000).to_le_bytes());
    event_data.extend_from_slice(&base_pid.to_le_bytes());
    
    let uid = unsafe { getuid() };
    event_data.extend_from_slice(&uid.to_le_bytes());
    event_data.extend_from_slice(&uid.to_le_bytes());
    
    let mut comm_bytes = [0u8; 16];
    let comm_data = comm.as_bytes();
    let len = std::cmp::min(comm_data.len(), 15);
    comm_bytes[..len].copy_from_slice(&comm_data[..len]);
    event_data.extend_from_slice(&comm_bytes);
    
    let mut filename_bytes = [0u8; 256];
    let filename_data = filepath.as_bytes();
    let len = std::cmp::min(filename_data.len(), 255);
    filename_bytes[..len].copy_from_slice(&filename_data[..len]);
    event_data.extend_from_slice(&filename_bytes);
    
    event_data.push(if id % 3 == 0 { 2 } else { 1 });
    event_data.extend_from_slice(&0i32.to_le_bytes());
    
    event_data
}

/// Create realistic process event
fn create_realistic_process_event(id: u32, comm: &str, filepath: &str) -> Vec<u8> {
    let mut event_data = Vec::with_capacity(400);
    
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    event_data.extend_from_slice(&timestamp.to_le_bytes());
    
    let base_pid = unsafe { getpid() } as u32;
    event_data.extend_from_slice(&(base_pid + id + 5000).to_le_bytes());
    
    // Simulate process chains - some processes have different parents
    let ppid = if id % 4 == 0 { 1 } else { base_pid + (id / 4) };
    event_data.extend_from_slice(&ppid.to_le_bytes());
    
    let uid = if id % 20 == 0 { 0 } else { unsafe { getuid() } }; // Occasional root processes
    event_data.extend_from_slice(&uid.to_le_bytes());
    event_data.extend_from_slice(&uid.to_le_bytes());
    
    let mut comm_bytes = [0u8; 16];
    let comm_data = comm.as_bytes();
    let len = std::cmp::min(comm_data.len(), 15);
    comm_bytes[..len].copy_from_slice(&comm_data[..len]);
    event_data.extend_from_slice(&comm_bytes);
    
    let mut filename_bytes = [0u8; 256];
    let filename_data = filepath.as_bytes();
    let len = std::cmp::min(filename_data.len(), 255);
    filename_bytes[..len].copy_from_slice(&filename_data[..len]);
    event_data.extend_from_slice(&filename_bytes);
    
    event_data.push(if id % 7 == 0 { 3 } else { 1 });
    event_data.extend_from_slice(&0i32.to_le_bytes());
    
    event_data
}

criterion_group!(
    benches,
    bench_event_parsing,
    bench_batch_processing,
    bench_concurrent_processing,
    bench_memory_allocation,
    bench_end_to_end_latency,
    bench_realistic_system_stress
);

criterion_main!(benches);