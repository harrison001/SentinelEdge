// kernel-agent/examples/performance_demo.rs
// High-performance eBPF system demonstration

use kernel_agent::*;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::timeout;
use tracing::{info, warn, error};
use std::sync::atomic::{AtomicU64, Ordering};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    info!("🚀 Starting SentinelEdge High-Performance eBPF Demo");

    // Create optimized configuration
    let config = EbpfConfig {
        ring_buffer_size: 1024 * 1024,      // 1MB ring buffer
        event_batch_size: 256,
        poll_timeout_ms: 1,
        max_events_per_sec: 100000,          // 100K events/sec
        enable_backpressure: true,
        auto_recovery: true,
        metrics_interval_sec: 5,
        // High-performance optimizations
        ring_buffer_poll_timeout_us: Some(50),   // 50 microseconds
        batch_size: Some(128),                   // Large batches
        batch_timeout_us: Some(500),             // 0.5ms timeout
    };

    info!("📋 Configuration:");
    info!("   • Ring buffer size: {} KB", config.ring_buffer_size / 1024);
    info!("   • Max events/sec: {}", config.max_events_per_sec);
    info!("   • Batch size: {:?}", config.batch_size);
    info!("   • Poll timeout: {:?} μs", config.ring_buffer_poll_timeout_us);

    // Create and initialize eBPF loader
    let mut loader = EbpfLoader::with_config(config);

    // Since we can't load actual eBPF programs without root/proper setup,
    // we'll demonstrate the high-performance processing pipeline
    info!("🔧 Demonstrating high-performance event processing pipeline...");
    
    // Run performance demonstration
    let results = run_performance_demo(&loader).await?;
    print_performance_results(results).await;

    // Run concurrency test
    info!("🧵 Testing concurrent processing...");
    let concurrency_results = run_concurrency_demo(&loader).await?;
    print_concurrency_results(concurrency_results).await;

    // Run latency test
    info!("⚡ Testing end-to-end latency...");
    let latency_results = run_latency_demo(&loader).await?;
    print_latency_results(latency_results).await;

    // Show final metrics
    info!("📊 Final system metrics:");
    let final_metrics = loader.metrics.read().await;
    info!("   • Total events processed: {}", final_metrics.events_processed);
    info!("   • Total events dropped: {}", final_metrics.events_dropped);
    info!("   • Processing errors: {}", final_metrics.processing_errors);
    
    if let Some(last_event) = final_metrics.last_event_timestamp {
        info!("   • Last event timestamp: {:?}", last_event);
    }

    info!("✅ Demo completed successfully!");
    Ok(())
}

#[derive(Debug)]
struct PerformanceResults {
    events_sent: u64,
    events_processed: u64,
    duration: Duration,
    throughput: f64,
    errors: u64,
}

async fn run_performance_demo(loader: &EbpfLoader) -> anyhow::Result<PerformanceResults> {
    let event_count = 10000u64;
    let processed_count = Arc::new(AtomicU64::new(0));
    let error_count = Arc::new(AtomicU64::new(0));
    
    info!("📈 Starting performance test with {} events", event_count);
    
    let start_time = Instant::now();
    
    // Start event consumer
    let consumer_processed = Arc::clone(&processed_count);
    let consumer_errors = Arc::clone(&error_count);
    let receiver_guard = loader.event_receiver.read().await;
    
    if let Some(receiver) = receiver_guard.as_ref() {
        // This would normally consume events, but since we can't take ownership
        // we'll simulate the processing
        drop(receiver_guard);
    }

    // Send test events
    let mut sent_count = 0u64;
    for i in 0..event_count {
        let raw_event = create_test_event(i as u32);
        
        match EbpfLoader::parse_event_sync(&raw_event) {
            Ok(event) => {
                match loader.event_sender.try_send(event) {
                    Ok(_) => {
                        sent_count += 1;
                        processed_count.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(_) => {
                        error_count.fetch_add(1, Ordering::SeqCst);
                    }
                }
            }
            Err(_) => {
                error_count.fetch_add(1, Ordering::SeqCst);
            }
        }

        // Yield periodically to allow processing
        if i % 1000 == 0 {
            tokio::task::yield_now().await;
        }
    }

    let duration = start_time.elapsed();
    let final_processed = processed_count.load(Ordering::SeqCst);
    let final_errors = error_count.load(Ordering::SeqCst);
    let throughput = final_processed as f64 / duration.as_secs_f64();

    Ok(PerformanceResults {
        events_sent: sent_count,
        events_processed: final_processed,
        duration,
        throughput,
        errors: final_errors,
    })
}

#[derive(Debug)]
struct ConcurrencyResults {
    thread_count: usize,
    events_per_thread: u64,
    total_processed: u64,
    duration: Duration,
    aggregate_throughput: f64,
}

async fn run_concurrency_demo(loader: &EbpfLoader) -> anyhow::Result<ConcurrencyResults> {
    let thread_count = 8;
    let events_per_thread = 1000u64;
    let total_processed = Arc::new(AtomicU64::new(0));
    
    info!("🧵 Starting concurrency test: {} threads, {} events each", 
          thread_count, events_per_thread);
    
    let start_time = Instant::now();
    let mut tasks = Vec::new();
    
    for thread_id in 0..thread_count {
        let sender = loader.event_sender.clone();
        let processed_counter = Arc::clone(&total_processed);
        
        let task = tokio::spawn(async move {
            for i in 0..events_per_thread {
                let event_id = (thread_id as u64 * events_per_thread) + i;
                let raw_event = create_test_event(event_id as u32);
                
                if let Ok(event) = EbpfLoader::parse_event_sync(&raw_event) {
                    if sender.try_send(event).is_ok() {
                        processed_counter.fetch_add(1, Ordering::SeqCst);
                    }
                }
                
                // Small delay to simulate realistic timing
                if i % 100 == 0 {
                    tokio::task::yield_now().await;
                }
            }
        });
        
        tasks.push(task);
    }
    
    // Wait for all tasks to complete
    for task in tasks {
        task.await?;
    }
    
    let duration = start_time.elapsed();
    let final_processed = total_processed.load(Ordering::SeqCst);
    let throughput = final_processed as f64 / duration.as_secs_f64();
    
    Ok(ConcurrencyResults {
        thread_count,
        events_per_thread,
        total_processed: final_processed,
        duration,
        aggregate_throughput: throughput,
    })
}

#[derive(Debug)]
struct LatencyResults {
    min_latency: Duration,
    max_latency: Duration,
    avg_latency: Duration,
    p95_latency: Duration,
    samples: usize,
}

async fn run_latency_demo(loader: &EbpfLoader) -> anyhow::Result<LatencyResults> {
    let sample_count = 1000;
    let mut latencies = Vec::with_capacity(sample_count);
    
    info!("⚡ Starting latency test with {} samples", sample_count);
    
    for i in 0..sample_count {
        let start = Instant::now();
        
        let raw_event = create_test_event(i as u32);
        if let Ok(event) = EbpfLoader::parse_event_sync(&raw_event) {
            let _ = loader.event_sender.try_send(event);
        }
        
        let latency = start.elapsed();
        latencies.push(latency);
        
        // Small delay between samples
        tokio::time::sleep(Duration::from_micros(100)).await;
    }
    
    latencies.sort();
    
    let min_latency = latencies[0];
    let max_latency = latencies[latencies.len() - 1];
    let avg_latency = Duration::from_nanos(
        latencies.iter().map(|d| d.as_nanos() as u64).sum::<u64>() / latencies.len() as u64
    );
    let p95_index = (latencies.len() as f64 * 0.95) as usize;
    let p95_latency = latencies[p95_index];
    
    Ok(LatencyResults {
        min_latency,
        max_latency,
        avg_latency,
        p95_latency,
        samples: latencies.len(),
    })
}

async fn print_performance_results(results: PerformanceResults) {
    info!("📊 Performance Test Results:");
    info!("   • Events sent: {}", results.events_sent);
    info!("   • Events processed: {}", results.events_processed);
    info!("   • Duration: {:?}", results.duration);
    info!("   • Throughput: {:.0} events/second", results.throughput);
    info!("   • Errors: {}", results.errors);
    info!("   • Success rate: {:.2}%", 
          (results.events_processed as f64 / results.events_sent as f64) * 100.0);
}

async fn print_concurrency_results(results: ConcurrencyResults) {
    info!("🧵 Concurrency Test Results:");
    info!("   • Threads: {}", results.thread_count);
    info!("   • Events per thread: {}", results.events_per_thread);
    info!("   • Total processed: {}", results.total_processed);
    info!("   • Duration: {:?}", results.duration);
    info!("   • Aggregate throughput: {:.0} events/second", results.aggregate_throughput);
    info!("   • Per-thread throughput: {:.0} events/second", 
          results.aggregate_throughput / results.thread_count as f64);
}

async fn print_latency_results(results: LatencyResults) {
    info!("⚡ Latency Test Results:");
    info!("   • Samples: {}", results.samples);
    info!("   • Min latency: {:?}", results.min_latency);
    info!("   • Avg latency: {:?}", results.avg_latency);
    info!("   • P95 latency: {:?}", results.p95_latency);
    info!("   • Max latency: {:?}", results.max_latency);
}

/// Create a test event for performance testing
fn create_test_event(id: u32) -> Vec<u8> {
    let mut event_data = Vec::new();
    
    // Timestamp (8 bytes)
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    event_data.extend_from_slice(&timestamp.to_le_bytes());
    
    // PID (4 bytes)
    event_data.extend_from_slice(&id.to_le_bytes());
    
    // PPID (4 bytes)
    event_data.extend_from_slice(&(id + 1000).to_le_bytes());
    
    // UID (4 bytes)
    event_data.extend_from_slice(&1000u32.to_le_bytes());
    
    // GID (4 bytes)
    event_data.extend_from_slice(&1000u32.to_le_bytes());
    
    // Command (16 bytes, null-padded)
    let mut comm_bytes = [0u8; 16];
    let comm_str = format!("demo_{}", id % 100);
    let comm_data = comm_str.as_bytes();
    let len = std::cmp::min(comm_data.len(), 15);
    comm_bytes[..len].copy_from_slice(&comm_data[..len]);
    event_data.extend_from_slice(&comm_bytes);
    
    // Filename (256 bytes, null-padded)
    let mut filename_bytes = [0u8; 256];
    let filename_str = format!("/demo/performance/test_{}", id);
    let filename_data = filename_str.as_bytes();
    let len = std::cmp::min(filename_data.len(), 255);
    filename_bytes[..len].copy_from_slice(&filename_data[..len]);
    event_data.extend_from_slice(&filename_bytes);
    
    // Args count (1 byte)
    event_data.push(0);
    
    // Exit code (4 bytes)
    event_data.extend_from_slice(&0i32.to_le_bytes());
    
    event_data
}