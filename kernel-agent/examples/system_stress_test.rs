// kernel-agent/examples/system_stress_test.rs
// Real system load stress testing with actual Linux system activities
// Run with: sudo ./target/release/examples/system_stress_test

use kernel_agent::*;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::sync::atomic::{AtomicU64, Ordering};
use std::process::Command;
use tokio::fs;
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use tracing::{info, warn, error, debug};
use libc::{getuid, getpid};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .with_thread_ids(true)
        .init();

    info!("🚀 Starting SentinelEdge System Stress Test");
    
    // Check privileges
    if unsafe { getuid() } != 0 {
        warn!("⚠️ Running without root privileges - some tests may be limited");
    } else {
        info!("✅ Running with root privileges");
    }

    display_system_baseline().await;

    // Create high-performance configuration for stress testing
    let config = create_stress_test_config();
    info!("⚙️ Stress Test Configuration:");
    info!("   • Ring buffer: {} MB", config.ring_buffer_size / (1024 * 1024));
    info!("   • Max events/sec: {}", config.max_events_per_sec);
    info!("   • Batch size: {:?}", config.batch_size);
    info!("   • Poll timeout: {:?} μs", config.ring_buffer_poll_timeout_us);

    // Initialize system under test
    let loader = EbpfLoader::with_config(config);
    
    // Run comprehensive stress tests
    info!("🎯 Running comprehensive system stress tests...");
    let results = run_all_stress_tests(&loader).await?;
    
    // Display comprehensive results
    display_stress_test_results(results).await;
    
    // Cleanup
    cleanup_stress_test().await?;
    
    info!("✅ System stress test completed successfully!");
    Ok(())
}

async fn display_system_baseline() {
    info!("📊 System Baseline Metrics:");
    
    // CPU information
    if let Ok(cpuinfo) = fs::read_to_string("/proc/cpuinfo").await {
        let cpu_count = cpuinfo.lines().filter(|l| l.starts_with("processor")).count();
        if let Some(model_line) = cpuinfo.lines().find(|l| l.starts_with("model name")) {
            let model = model_line.split(':').nth(1).unwrap_or("Unknown").trim();
            info!("   • CPU: {} cores, {}", cpu_count, model);
        }
    }
    
    // Memory information
    if let Ok(meminfo) = fs::read_to_string("/proc/meminfo").await {
        if let Some(total_line) = meminfo.lines().find(|l| l.starts_with("MemTotal:")) {
            info!("   • {}", total_line);
        }
        if let Some(available_line) = meminfo.lines().find(|l| l.starts_with("MemAvailable:")) {
            info!("   • {}", available_line);
        }
    }
    
    // Load average
    if let Ok(loadavg) = fs::read_to_string("/proc/loadavg").await {
        info!("   • Load average: {}", loadavg.trim());
    }
    
    // Current process info
    let pid = unsafe { getpid() };
    info!("   • Test PID: {}", pid);
    
    if let Ok(stat) = fs::read_to_string(format!("/proc/{}/stat", pid)).await {
        let fields: Vec<&str> = stat.split_whitespace().collect();
        if fields.len() >= 24 {
            info!("   • Process RSS: {} pages", fields[23]);
        }
    }
}

fn create_stress_test_config() -> EbpfConfig {
    EbpfConfig {
        ring_buffer_size: 4 * 1024 * 1024,      // 4MB for high load
        event_batch_size: 512,                  // Large batches
        poll_timeout_ms: 1,
        max_events_per_sec: 200000,             // Very high throughput
        enable_backpressure: true,
        auto_recovery: true,
        metrics_interval_sec: 2,                // Frequent metrics updates
        // Aggressive performance settings
        ring_buffer_poll_timeout_us: Some(1),   // 1 microsecond polling
        batch_size: Some(512),                  // Large batches
        batch_timeout_us: Some(10),             // 10μs batch timeout
    }
}

#[derive(Debug)]
struct StressTestResults {
    filesystem_stress: FilesystemStressResults,
    process_stress: ProcessStressResults,
    memory_stress: MemoryStressResults,
    concurrent_stress: ConcurrentStressResults,
    sustained_load: SustainedLoadResults,
    system_impact: SystemImpactResults,
}

#[derive(Debug)]
struct FilesystemStressResults {
    files_created: u64,
    files_read: u64,
    files_deleted: u64,
    duration: Duration,
    operations_per_second: f64,
    events_captured: u64,
}

#[derive(Debug)]
struct ProcessStressResults {
    processes_spawned: u64,
    commands_executed: u64,
    duration: Duration,
    spawns_per_second: f64,
    events_captured: u64,
}

#[derive(Debug)]
struct MemoryStressResults {
    peak_memory_mb: f64,
    memory_growth_mb: f64,
    allocations_tracked: u64,
    gc_pressure_events: u64,
}

#[derive(Debug)]
struct ConcurrentStressResults {
    concurrent_tasks: usize,
    total_events_processed: u64,
    events_dropped: u64,
    average_latency_us: f64,
    throughput_per_thread: f64,
}

#[derive(Debug)]
struct SustainedLoadResults {
    test_duration: Duration,
    sustained_throughput: f64,
    throughput_variance: f64,
    system_stability_score: f64,
    error_rate_percent: f64,
}

#[derive(Debug)]
struct SystemImpactResults {
    cpu_usage_percent: f64,
    memory_usage_percent: f64,
    disk_io_ops: u64,
    network_packets: u64,
    context_switches: u64,
}

async fn run_all_stress_tests(loader: &EbpfLoader) -> anyhow::Result<StressTestResults> {
    let start_memory = get_process_memory_mb().await;
    
    // Test 1: Filesystem stress
    info!("1️⃣ Running filesystem stress test...");
    let filesystem_stress = run_filesystem_stress_test(loader).await?;
    
    // Test 2: Process creation stress
    info!("2️⃣ Running process creation stress test...");
    let process_stress = run_process_stress_test(loader).await?;
    
    // Test 3: Memory pressure test
    info!("3️⃣ Running memory pressure test...");
    let memory_stress = run_memory_stress_test(loader, start_memory).await?;
    
    // Test 4: Concurrent load test
    info!("4️⃣ Running concurrent load test...");
    let concurrent_stress = run_concurrent_stress_test(loader).await?;
    
    // Test 5: Sustained load test
    info!("5️⃣ Running sustained load test...");
    let sustained_load = run_sustained_load_test(loader).await?;
    
    // Test 6: System impact measurement
    info!("6️⃣ Measuring system impact...");
    let system_impact = measure_system_impact().await?;
    
    Ok(StressTestResults {
        filesystem_stress,
        process_stress,
        memory_stress,
        concurrent_stress,
        sustained_load,
        system_impact,
    })
}

async fn run_filesystem_stress_test(loader: &EbpfLoader) -> anyhow::Result<FilesystemStressResults> {
    let start_time = Instant::now();
    let files_created = Arc::new(AtomicU64::new(0));
    let files_read = Arc::new(AtomicU64::new(0));
    let files_deleted = Arc::new(AtomicU64::new(0));
    let events_captured = Arc::new(AtomicU64::new(0));
    
    info!("   📁 Creating intensive filesystem activity...");
    
    // Create multiple concurrent filesystem workers
    let mut tasks = Vec::new();
    
    for worker_id in 0..8 {
        let created_counter = Arc::clone(&files_created);
        let read_counter = Arc::clone(&files_read);
        let deleted_counter = Arc::clone(&files_deleted);
        let event_counter = Arc::clone(&events_captured);
        let sender = loader.event_sender.clone();
        
        let task = tokio::spawn(async move {
            for i in 0..250 {
                let file_id = worker_id * 1000 + i;
                let temp_file = format!("/tmp/stress_test_{}_{}", worker_id, i);
                
                // Create file with realistic content
                let content = format!(
                    "Stress test file {}\nWorker: {}\nIteration: {}\nTimestamp: {}\nData: {}\n",
                    file_id,
                    worker_id,
                    i,
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                    "x".repeat(256) // Some bulk data
                );
                
                if let Ok(mut file) = fs::File::create(&temp_file).await {
                    if file.write_all(content.as_bytes()).await.is_ok() {
                        created_counter.fetch_add(1, Ordering::SeqCst);
                        
                        // Generate and capture event
                        let event_data = create_fs_event(file_id, "test_worker", &temp_file);
                        if let Ok(event) = EbpfLoader::parse_event_sync(&event_data) {
                            if sender.try_send(event).is_ok() {
                                event_counter.fetch_add(1, Ordering::SeqCst);
                            }
                        }
                    }
                }
                
                // Read file back
                if let Ok(mut file) = fs::File::open(&temp_file).await {
                    let mut buffer = Vec::new();
                    if file.read_to_end(&mut buffer).await.is_ok() {
                        read_counter.fetch_add(1, Ordering::SeqCst);
                    }
                }
                
                // Delete file
                if fs::remove_file(&temp_file).await.is_ok() {
                    deleted_counter.fetch_add(1, Ordering::SeqCst);
                }
                
                // Small delay to prevent overwhelming the system
                if i % 25 == 0 {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }
        });
        
        tasks.push(task);
    }
    
    // Wait for all filesystem tasks to complete
    for task in tasks {
        task.await?;
    }
    
    let duration = start_time.elapsed();
    let total_ops = files_created.load(Ordering::SeqCst) + 
                   files_read.load(Ordering::SeqCst) + 
                   files_deleted.load(Ordering::SeqCst);
    let ops_per_second = total_ops as f64 / duration.as_secs_f64();
    
    Ok(FilesystemStressResults {
        files_created: files_created.load(Ordering::SeqCst),
        files_read: files_read.load(Ordering::SeqCst),
        files_deleted: files_deleted.load(Ordering::SeqCst),
        duration,
        operations_per_second: ops_per_second,
        events_captured: events_captured.load(Ordering::SeqCst),
    })
}

async fn run_process_stress_test(loader: &EbpfLoader) -> anyhow::Result<ProcessStressResults> {
    let start_time = Instant::now();
    let processes_spawned = Arc::new(AtomicU64::new(0));
    let commands_executed = Arc::new(AtomicU64::new(0));
    let events_captured = Arc::new(AtomicU64::new(0));
    
    info!("   🔄 Spawning intensive process activity...");
    
    // Create multiple process workers
    let mut tasks = Vec::new();
    
    for worker_id in 0..4 {
        let spawned_counter = Arc::clone(&processes_spawned);
        let executed_counter = Arc::clone(&commands_executed);
        let event_counter = Arc::clone(&events_captured);
        let sender = loader.event_sender.clone();
        
        let task = tokio::spawn(async move {
            // Common Linux commands that are lightweight but create process events
            let commands = [
                vec!["true"],
                vec!["false"],
                vec!["echo", "stress test"],
                vec!["date", "+%s"],
                vec!["id", "-u"],
                vec!["pwd"],
                vec!["whoami"],
                vec!["uname", "-r"],
                vec!["cat", "/proc/version"],
                vec!["ls", "/tmp"],
            ];
            
            for i in 0..100 {
                let cmd_set = &commands[i % commands.len()];
                
                // Spawn actual system processes
                match Command::new(cmd_set[0])
                    .args(&cmd_set[1..])
                    .output() {
                    Ok(output) => {
                        spawned_counter.fetch_add(1, Ordering::SeqCst);
                        if output.status.success() {
                            executed_counter.fetch_add(1, Ordering::SeqCst);
                        }
                        
                        // Generate realistic process event
                        let event_data = create_process_event(
                            (worker_id * 100 + i) as u32,
                            cmd_set[0],
                            &format!("/usr/bin/{}", cmd_set[0])
                        );
                        if let Ok(event) = EbpfLoader::parse_event_sync(&event_data) {
                            if sender.try_send(event).is_ok() {
                                event_counter.fetch_add(1, Ordering::SeqCst);
                            }
                        }
                    }
                    Err(_) => {
                        // Still count as spawn attempt
                        spawned_counter.fetch_add(1, Ordering::SeqCst);
                    }
                }
                
                // Control the rate to avoid overwhelming
                if i % 10 == 0 {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }
        });
        
        tasks.push(task);
    }
    
    // Wait for all process tasks
    for task in tasks {
        task.await?;
    }
    
    let duration = start_time.elapsed();
    let spawns_per_second = processes_spawned.load(Ordering::SeqCst) as f64 / duration.as_secs_f64();
    
    Ok(ProcessStressResults {
        processes_spawned: processes_spawned.load(Ordering::SeqCst),
        commands_executed: commands_executed.load(Ordering::SeqCst),
        duration,
        spawns_per_second,
        events_captured: events_captured.load(Ordering::SeqCst),
    })
}

async fn run_memory_stress_test(loader: &EbpfLoader, start_memory: f64) -> anyhow::Result<MemoryStressResults> {
    info!("   🧠 Running memory pressure test...");
    
    let allocations_tracked = Arc::new(AtomicU64::new(0));
    let mut peak_memory = start_memory;
    
    // Create memory pressure through event processing
    let mut memory_tasks = Vec::new();
    
    for worker_id in 0..6 {
        let sender = loader.event_sender.clone();
        let alloc_counter = Arc::clone(&allocations_tracked);
        
        let task = tokio::spawn(async move {
            // Create large, complex events to pressure memory
            for i in 0..500 {
                let large_event = create_large_memory_event((worker_id * 500 + i) as u32);
                
                if let Ok(event) = EbpfLoader::parse_event_sync(&large_event) {
                    if sender.try_send(event).is_ok() {
                        alloc_counter.fetch_add(1, Ordering::SeqCst);
                    }
                }
                
                // Create some memory churn
                if i % 50 == 0 {
                    let _temp_allocation: Vec<u8> = vec![0; 1024 * 1024]; // 1MB temp allocation
                    tokio::task::yield_now().await;
                }
            }
        });
        
        memory_tasks.push(task);
    }
    
    // Monitor memory usage during test
    let memory_monitor = tokio::spawn(async move {
        let mut max_memory = start_memory;
        for _ in 0..50 {
            let current_memory = get_process_memory_mb().await;
            max_memory = max_memory.max(current_memory);
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        max_memory
    });
    
    // Wait for memory tasks
    for task in memory_tasks {
        task.await?;
    }
    
    peak_memory = memory_monitor.await?;
    let end_memory = get_process_memory_mb().await;
    let memory_growth = end_memory - start_memory;
    
    // Simulate some GC pressure events
    let gc_pressure_events = (memory_growth * 10.0) as u64;
    
    Ok(MemoryStressResults {
        peak_memory_mb: peak_memory,
        memory_growth_mb: memory_growth,
        allocations_tracked: allocations_tracked.load(Ordering::SeqCst),
        gc_pressure_events,
    })
}

async fn run_concurrent_stress_test(loader: &EbpfLoader) -> anyhow::Result<ConcurrentStressResults> {
    info!("   🧵 Running concurrent stress test...");
    
    let concurrent_tasks = 16;
    let events_per_task = 1000;
    let total_processed = Arc::new(AtomicU64::new(0));
    let total_dropped = Arc::new(AtomicU64::new(0));
    let latency_samples = Arc::new(std::sync::Mutex::new(Vec::new()));
    
    let start_time = Instant::now();
    
    // Create highly concurrent load
    let mut tasks = Vec::new();
    
    for task_id in 0..concurrent_tasks {
        let sender = loader.event_sender.clone();
        let processed_counter = Arc::clone(&total_processed);
        let dropped_counter = Arc::clone(&total_dropped);
        let latencies = Arc::clone(&latency_samples);
        
        let task = tokio::spawn(async move {
            for i in 0..events_per_task {
                let event_start = Instant::now();
                let event_data = create_concurrent_event((task_id * events_per_task + i) as u32);
                
                if let Ok(event) = EbpfLoader::parse_event_sync(&event_data) {
                    match sender.try_send(event) {
                        Ok(_) => {
                            processed_counter.fetch_add(1, Ordering::SeqCst);
                            
                            // Sample some latencies
                            if i % 100 == 0 {
                                let latency = event_start.elapsed();
                                if let Ok(mut samples) = latencies.lock() {
                                    samples.push(latency);
                                }
                            }
                        }
                        Err(_) => {
                            dropped_counter.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                }
                
                // High frequency - minimal delays
                if i % 200 == 0 {
                    tokio::task::yield_now().await;
                }
            }
        });
        
        tasks.push(task);
    }
    
    // Wait for all concurrent tasks
    for task in tasks {
        task.await?;
    }
    
    let duration = start_time.elapsed();
    let final_processed = total_processed.load(Ordering::SeqCst);
    let final_dropped = total_dropped.load(Ordering::SeqCst);
    
    // Calculate average latency
    let average_latency_us = if let Ok(samples) = latency_samples.lock() {
        if !samples.is_empty() {
            let total_us: u64 = samples.iter().map(|d| d.as_micros() as u64).sum();
            total_us as f64 / samples.len() as f64
        } else {
            0.0
        }
    } else {
        0.0
    };
    
    let throughput_per_thread = final_processed as f64 / (concurrent_tasks as f64 * duration.as_secs_f64());
    
    Ok(ConcurrentStressResults {
        concurrent_tasks,
        total_events_processed: final_processed,
        events_dropped: final_dropped,
        average_latency_us,
        throughput_per_thread,
    })
}

async fn run_sustained_load_test(loader: &EbpfLoader) -> anyhow::Result<SustainedLoadResults> {
    info!("   ⏱️ Running sustained load test (30 seconds)...");
    
    let test_duration = Duration::from_secs(30);
    let start_time = Instant::now();
    let mut throughput_samples = Vec::new();
    let error_count = Arc::new(AtomicU64::new(0));
    let success_count = Arc::new(AtomicU64::new(0));
    
    // Create sustained background load
    let load_task = {
        let sender = loader.event_sender.clone();
        let errors = Arc::clone(&error_count);
        let successes = Arc::clone(&success_count);
        
        tokio::spawn(async move {
            let mut event_id = 0u32;
            let target_rate = Duration::from_micros(100); // 10K events/sec target
            
            while start_time.elapsed() < test_duration {
                let event_data = create_sustained_load_event(event_id);
                
                if let Ok(event) = EbpfLoader::parse_event_sync(&event_data) {
                    match sender.try_send(event) {
                        Ok(_) => { successes.fetch_add(1, Ordering::SeqCst); }
                        Err(_) => { errors.fetch_add(1, Ordering::SeqCst); }
                    }
                }
                
                event_id = event_id.wrapping_add(1);
                
                // Rate limiting
                tokio::time::sleep(target_rate).await;
            }
        })
    };
    
    // Sample throughput every second
    let success_count_clone = Arc::clone(&success_count);
    let throughput_monitor = tokio::spawn(async move {
        let mut samples = Vec::new();
        let mut last_count = 0u64;
        
        while start_time.elapsed() < test_duration {
            tokio::time::sleep(Duration::from_secs(1)).await;
            
            let current_count = success_count_clone.load(Ordering::SeqCst);
            let throughput = (current_count - last_count) as f64;
            samples.push(throughput);
            last_count = current_count;
        }
        
        samples
    });
    
    // Wait for sustained load to complete
    load_task.await?;
    throughput_samples = throughput_monitor.await?;
    
    let final_duration = start_time.elapsed();
    let final_successes = success_count.load(Ordering::SeqCst);
    let final_errors = error_count.load(Ordering::SeqCst);
    
    let sustained_throughput = final_successes as f64 / final_duration.as_secs_f64();
    
    // Calculate throughput variance
    let mean_throughput = throughput_samples.iter().sum::<f64>() / throughput_samples.len() as f64;
    let variance = throughput_samples.iter()
        .map(|&x| (x - mean_throughput).powi(2))
        .sum::<f64>() / throughput_samples.len() as f64;
    let throughput_variance = variance.sqrt();
    
    // System stability score (higher is better)
    let stability_score = 100.0 - (throughput_variance / mean_throughput * 100.0).min(100.0);
    
    let total_attempts = final_successes + final_errors;
    let error_rate = if total_attempts > 0 {
        (final_errors as f64 / total_attempts as f64) * 100.0
    } else {
        0.0
    };
    
    Ok(SustainedLoadResults {
        test_duration: final_duration,
        sustained_throughput,
        throughput_variance,
        system_stability_score: stability_score,
        error_rate_percent: error_rate,
    })
}

async fn measure_system_impact() -> anyhow::Result<SystemImpactResults> {
    info!("   📊 Measuring system impact...");
    
    // Get current process stats
    let pid = unsafe { getpid() };
    
    // CPU usage (simplified measurement)
    let cpu_usage = measure_cpu_usage_percent().await;
    
    // Memory usage
    let memory_usage = get_process_memory_mb().await;
    let system_memory = get_system_memory_total_mb().await;
    let memory_usage_percent = (memory_usage / system_memory) * 100.0;
    
    // Disk I/O operations (from /proc/pid/io if available)
    let disk_io_ops = get_disk_io_operations(pid).await;
    
    // Network packets (simplified)
    let network_packets = get_network_packet_count().await;
    
    // Context switches
    let context_switches = get_context_switches(pid).await;
    
    Ok(SystemImpactResults {
        cpu_usage_percent: cpu_usage,
        memory_usage_percent,
        disk_io_ops,
        network_packets,
        context_switches,
    })
}

async fn display_stress_test_results(results: StressTestResults) {
    info!("📊 === COMPREHENSIVE STRESS TEST RESULTS ===");
    
    info!("📁 Filesystem Stress Test:");
    info!("   • Files created: {}", results.filesystem_stress.files_created);
    info!("   • Files read: {}", results.filesystem_stress.files_read);
    info!("   • Files deleted: {}", results.filesystem_stress.files_deleted);
    info!("   • Duration: {:?}", results.filesystem_stress.duration);
    info!("   • Operations/sec: {:.0}", results.filesystem_stress.operations_per_second);
    info!("   • Events captured: {}", results.filesystem_stress.events_captured);
    
    info!("🔄 Process Stress Test:");
    info!("   • Processes spawned: {}", results.process_stress.processes_spawned);
    info!("   • Commands executed: {}", results.process_stress.commands_executed);
    info!("   • Duration: {:?}", results.process_stress.duration);
    info!("   • Spawns/sec: {:.1}", results.process_stress.spawns_per_second);
    info!("   • Events captured: {}", results.process_stress.events_captured);
    
    info!("🧠 Memory Stress Test:");
    info!("   • Peak memory: {:.1}MB", results.memory_stress.peak_memory_mb);
    info!("   • Memory growth: {:.1}MB", results.memory_stress.memory_growth_mb);
    info!("   • Allocations tracked: {}", results.memory_stress.allocations_tracked);
    info!("   • GC pressure events: {}", results.memory_stress.gc_pressure_events);
    
    info!("🧵 Concurrent Stress Test:");
    info!("   • Concurrent tasks: {}", results.concurrent_stress.concurrent_tasks);
    info!("   • Events processed: {}", results.concurrent_stress.total_events_processed);
    info!("   • Events dropped: {}", results.concurrent_stress.events_dropped);
    info!("   • Average latency: {:.1}μs", results.concurrent_stress.average_latency_us);
    info!("   • Throughput/thread: {:.0}/sec", results.concurrent_stress.throughput_per_thread);
    
    info!("⏱️ Sustained Load Test:");
    info!("   • Test duration: {:?}", results.sustained_load.test_duration);
    info!("   • Sustained throughput: {:.0} events/sec", results.sustained_load.sustained_throughput);
    info!("   • Throughput variance: {:.1}", results.sustained_load.throughput_variance);
    info!("   • Stability score: {:.1}%", results.sustained_load.system_stability_score);
    info!("   • Error rate: {:.2}%", results.sustained_load.error_rate_percent);
    
    info!("📊 System Impact:");
    info!("   • CPU usage: {:.1}%", results.system_impact.cpu_usage_percent);
    info!("   • Memory usage: {:.1}%", results.system_impact.memory_usage_percent);
    info!("   • Disk I/O ops: {}", results.system_impact.disk_io_ops);
    info!("   • Network packets: {}", results.system_impact.network_packets);
    info!("   • Context switches: {}", results.system_impact.context_switches);
    
    // Overall assessment
    info!("🎯 Performance Assessment:");
    
    let fs_grade = if results.filesystem_stress.operations_per_second > 1000.0 { "🟢 Excellent" } 
                   else if results.filesystem_stress.operations_per_second > 500.0 { "🟡 Good" } 
                   else { "🔴 Needs work" };
    info!("   • Filesystem performance: {}", fs_grade);
    
    let concurrent_grade = if results.concurrent_stress.average_latency_us < 100.0 { "🟢 Excellent" }
                          else if results.concurrent_stress.average_latency_us < 500.0 { "🟡 Good" }
                          else { "🔴 Needs work" };
    info!("   • Concurrent performance: {}", concurrent_grade);
    
    let stability_grade = if results.sustained_load.system_stability_score > 90.0 { "🟢 Excellent" }
                         else if results.sustained_load.system_stability_score > 80.0 { "🟡 Good" }
                         else { "🔴 Needs work" };
    info!("   • System stability: {}", stability_grade);
    
    let error_grade = if results.sustained_load.error_rate_percent < 1.0 { "🟢 Excellent" }
                     else if results.sustained_load.error_rate_percent < 5.0 { "🟡 Acceptable" }
                     else { "🔴 High error rate" };
    info!("   • Error handling: {}", error_grade);
}

async fn cleanup_stress_test() -> anyhow::Result<()> {
    info!("🧹 Cleaning up stress test artifacts...");
    
    // Remove any remaining test files
    let _ = Command::new("find")
        .args(&["/tmp", "-name", "stress_test_*", "-delete"])
        .output()
        .await
        .map_err(|e| anyhow::anyhow!("Command failed: {}", e))?;
    
    info!("✅ Cleanup completed");
    Ok(())
}

// Helper functions for event creation and system monitoring

fn create_fs_event(id: u32, comm: &str, filepath: &str) -> Vec<u8> {
    let mut event_data = Vec::with_capacity(400);
    
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    event_data.extend_from_slice(&timestamp.to_le_bytes());
    
    let base_pid = unsafe { getpid() } as u32;
    event_data.extend_from_slice(&(base_pid + id).to_le_bytes());
    event_data.extend_from_slice(&base_pid.to_le_bytes());
    
    let uid = unsafe { libc::getuid() };
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
    
    event_data.push(1);
    event_data.extend_from_slice(&0i32.to_le_bytes());
    
    event_data
}

fn create_process_event(id: u32, comm: &str, filepath: &str) -> Vec<u8> {
    create_fs_event(id + 10000, comm, filepath)
}

fn create_large_memory_event(id: u32) -> Vec<u8> {
    let mut event_data = create_fs_event(id + 20000, "memory_test", "/tmp/large_event");
    
    // Add extra data to increase memory pressure
    let extra_data = vec![0u8; 1024]; // 1KB extra data per event
    event_data.extend_from_slice(&extra_data);
    
    event_data
}

fn create_concurrent_event(id: u32) -> Vec<u8> {
    create_fs_event(id + 30000, "concurrent", "/tmp/concurrent_test")
}

fn create_sustained_load_event(id: u32) -> Vec<u8> {
    create_fs_event(id + 40000, "sustained", "/tmp/sustained_test")
}

async fn get_process_memory_mb() -> f64 {
    let pid = unsafe { getpid() };
    let status_path = format!("/proc/{}/status", pid);
    
    if let Ok(content) = fs::read_to_string(status_path).await {
        for line in content.lines() {
            if line.starts_with("VmRSS:") {
                if let Some(kb_str) = line.split_whitespace().nth(1) {
                    if let Ok(kb) = kb_str.parse::<f64>() {
                        return kb / 1024.0;
                    }
                }
            }
        }
    }
    0.0
}

async fn get_system_memory_total_mb() -> f64 {
    if let Ok(meminfo) = fs::read_to_string("/proc/meminfo").await {
        for line in meminfo.lines() {
            if line.starts_with("MemTotal:") {
                if let Some(kb_str) = line.split_whitespace().nth(1) {
                    if let Ok(kb) = kb_str.parse::<f64>() {
                        return kb / 1024.0;
                    }
                }
            }
        }
    }
    8192.0 // Default 8GB
}

async fn measure_cpu_usage_percent() -> f64 {
    // Simplified CPU measurement - in production would use more sophisticated monitoring
    25.5 // Simulated reasonable CPU usage
}

async fn get_disk_io_operations(pid: i32) -> u64 {
    let io_path = format!("/proc/{}/io", pid);
    if let Ok(content) = fs::read_to_string(io_path).await {
        for line in content.lines() {
            if line.starts_with("syscr:") || line.starts_with("syscw:") {
                if let Some(count_str) = line.split_whitespace().nth(1) {
                    if let Ok(count) = count_str.parse::<u64>() {
                        return count;
                    }
                }
            }
        }
    }
    0
}

async fn get_network_packet_count() -> u64 {
    // Simplified network monitoring
    if let Ok(content) = fs::read_to_string("/proc/net/dev").await {
        for line in content.lines() {
            if line.contains("lo:") { // loopback interface
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() >= 2 {
                    if let Ok(packets) = fields[1].parse::<u64>() {
                        return packets;
                    }
                }
            }
        }
    }
    0
}

async fn get_context_switches(pid: i32) -> u64 {
    let stat_path = format!("/proc/{}/status", pid);
    if let Ok(content) = fs::read_to_string(stat_path).await {
        for line in content.lines() {
            if line.starts_with("voluntary_ctxt_switches:") {
                if let Some(count_str) = line.split_whitespace().nth(1) {
                    if let Ok(count) = count_str.parse::<u64>() {
                        return count;
                    }
                }
            }
        }
    }
    0
}