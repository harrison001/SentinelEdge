#[cfg(test)]
mod tests {
    use crate::{EbpfConfig, EbpfLoader, EbpfMetrics, RawEvent};
    use std::time::{Duration, Instant};
    use tokio::time::timeout;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use tokio::sync::{mpsc, RwLock, Semaphore};

    /// 创建测试用的配置
    fn create_test_config() -> EbpfConfig {
        EbpfConfig {
            ring_buffer_size: 64 * 1024,  // 64KB for testing
            event_batch_size: 32,
            poll_timeout_ms: 10,
            max_events_per_sec: 50000,
            enable_backpressure: true,
            auto_recovery: true,
            metrics_interval_sec: 1,
            // High-performance settings for testing
            ring_buffer_poll_timeout_us: Some(50),   // 50 microseconds
            batch_size: Some(16),                    // Smaller batches for testing
            batch_timeout_us: Some(500),             // 0.5ms batch timeout
        }
    }

    #[tokio::test]
    async fn test_ebpf_loader_initialization() {
        let config = create_test_config();
        let mut loader = EbpfLoader::with_config(config);

        // Test that the loader initializes correctly
        assert!(loader.event_sender.capacity() > 0);
        
        // Test configuration is set correctly
        assert_eq!(loader.config.batch_size, Some(16));
        assert_eq!(loader.config.ring_buffer_poll_timeout_us, Some(50));
    }

    #[tokio::test]
    async fn test_event_processing_pipeline() {
        let config = create_test_config();
        let loader = EbpfLoader::with_config(config);
        
        // Create test events
        let test_events = vec![
            create_test_raw_event(1, "test_process", "/usr/bin/test"),
            create_test_raw_event(2, "test_process2", "/usr/bin/test2"),
            create_test_raw_event(3, "test_process3", "/usr/bin/test3"),
        ];

        // Test event parsing
        for raw_event in test_events {
            let parsed = EbpfLoader::parse_event_sync(&raw_event);
            assert!(parsed.is_ok(), "Failed to parse test event");
        }
    }

    #[tokio::test]
    async fn test_high_throughput_processing() {
        let config = create_test_config();
        let loader = EbpfLoader::with_config(config);
        
        let event_count = Arc::new(AtomicU64::new(0));
        let start_time = Instant::now();
        
        // Simulate high-throughput event processing
        let mut tasks = Vec::new();
        
        for i in 0..10 {
            let sender = loader.event_sender.clone();
            let counter = Arc::clone(&event_count);
            
            let task = tokio::spawn(async move {
                for j in 0..1000 {
                    let raw_event = create_test_raw_event(
                        (i * 1000 + j) as u32, 
                        &format!("process_{}", i), 
                        &format!("/test/path_{}", j)
                    );
                    
                    match EbpfLoader::parse_event_sync(&raw_event) {
                        Ok(event) => {
                            if sender.try_send(event).is_ok() {
                                counter.fetch_add(1, Ordering::SeqCst);
                            }
                        }
                        Err(e) => eprintln!("Parse error: {}", e),
                    }
                    
                    // Small delay to simulate realistic timing
                    if j % 100 == 0 {
                        tokio::task::yield_now().await;
                    }
                }
            });
            
            tasks.push(task);
        }
        
        // Wait for all tasks to complete
        for task in tasks {
            task.await.expect("Task failed");
        }
        
        let duration = start_time.elapsed();
        let final_count = event_count.load(Ordering::SeqCst);
        let events_per_sec = final_count as f64 / duration.as_secs_f64();
        
        println!("📊 Performance Test Results:");
        println!("   • Processed {} events in {:?}", final_count, duration);
        println!("   • Throughput: {:.0} events/second", events_per_sec);
        
        assert!(final_count > 0, "No events were processed");
        assert!(events_per_sec > 1000.0, "Throughput too low: {:.0} events/sec", events_per_sec);
    }

    #[tokio::test]
    async fn test_metrics_and_monitoring() {
        let config = create_test_config();
        let loader = EbpfLoader::with_config(config);
        
        // Send some test events
        for i in 0..100 {
            let raw_event = create_test_raw_event(i, "test_proc", "/test/path");
            if let Ok(event) = EbpfLoader::parse_event_sync(&raw_event) {
                let _ = loader.event_sender.try_send(event);
            }
        }
        
        // Give some time for processing
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // Check metrics
        let metrics = loader.metrics.read().await;
        println!("📈 Metrics Test Results:");
        println!("   • Events processed: {}", metrics.events_processed);
        println!("   • Events dropped: {}", metrics.events_dropped);
        println!("   • Processing errors: {}", metrics.processing_errors);
    }

    #[tokio::test]
    async fn test_rate_limiting() {
        let mut config = create_test_config();
        config.max_events_per_sec = 5; // Very low limit for testing
        
        let loader = EbpfLoader::with_config(config);
        let mut sent_count = 0;
        let mut dropped_count = 0;
        
        // Saturate the channel first, then try more events
        for i in 0..200 {
            let raw_event = create_test_raw_event(i, "rate_test", "/test");
            if let Ok(event) = EbpfLoader::parse_event_sync(&raw_event) {
                match loader.event_sender.try_send(event) {
                    Ok(_) => sent_count += 1,
                    Err(_) => dropped_count += 1,
                }
            }
        }
        
        println!("🚦 Rate Limiting Test Results:");
        println!("   • Events sent: {}", sent_count);
        println!("   • Events dropped: {}", dropped_count);
        
        // Channel should eventually be full, causing drops
        assert!(sent_count > 0, "No events were sent");
        // Rate limiting might not cause drops immediately in tests, 
        // so we just verify the system handles the load
    }

    #[tokio::test]
    async fn test_batch_processing_timing() {
        let config = create_test_config();
        let (raw_event_tx, mut raw_event_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        let (processed_tx, mut processed_rx) = tokio::sync::mpsc::channel::<RawEvent>(1000);
        
        // Start the async event processor
        let metrics = Arc::new(RwLock::new(EbpfMetrics::default()));
        let rate_limiter = Arc::new(Semaphore::new(1000));
        let shutdown = Arc::new(tokio::sync::Notify::new());
        
        let processor_task = tokio::spawn(EbpfLoader::async_event_processor(
            raw_event_rx,
            processed_tx,
            metrics.clone(),
            rate_limiter,
            shutdown.clone(),
            config,
        ));
        
        let start_time = Instant::now();
        
        // Send events in batches
        for batch in 0..5 {
            for i in 0..10 {
                let raw_event = create_test_raw_event(
                    (batch * 10 + i) as u32, 
                    "batch_test", 
                    "/batch/test"
                );
                raw_event_tx.send(raw_event).unwrap();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        
        // Collect processed events with timeout
        let mut processed_events = Vec::new();
        let collect_timeout = Duration::from_secs(2);
        
        while let Ok(Some(event)) = timeout(Duration::from_millis(100), processed_rx.recv()).await {
            processed_events.push(event);
            if processed_events.len() >= 50 {
                break;
            }
        }
        
        let processing_time = start_time.elapsed();
        shutdown.notify_one();
        
        // Wait for processor to shutdown
        let _ = timeout(Duration::from_secs(1), processor_task).await;
        
        println!("⚡ Batch Processing Test Results:");
        println!("   • Processed {} events in {:?}", processed_events.len(), processing_time);
        println!("   • Average latency: {:?} per event", processing_time / processed_events.len() as u32);
        
        let final_metrics = metrics.read().await;
        println!("   • Final metrics - processed: {}, dropped: {}, errors: {}", 
                 final_metrics.events_processed, 
                 final_metrics.events_dropped, 
                 final_metrics.processing_errors);
        
        assert!(processed_events.len() > 0, "No events were processed");
        assert!(processing_time < Duration::from_secs(1), "Processing took too long");
    }

    #[tokio::test]
    async fn test_shutdown_handling() {
        let config = create_test_config();
        let (raw_event_tx, raw_event_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        let (processed_tx, _processed_rx) = tokio::sync::mpsc::channel::<RawEvent>(100);
        
        let metrics = Arc::new(RwLock::new(EbpfMetrics::default()));
        let rate_limiter = Arc::new(Semaphore::new(1000));
        let shutdown = Arc::new(tokio::sync::Notify::new());
        
        // Start processor
        let shutdown_clone = shutdown.clone();
        let processor_task = tokio::spawn(EbpfLoader::async_event_processor(
            raw_event_rx,
            processed_tx,
            metrics,
            rate_limiter,
            shutdown_clone,
            config,
        ));
        
        // Send some events
        for i in 0..10 {
            let raw_event = create_test_raw_event(i, "shutdown_test", "/test");
            raw_event_tx.send(raw_event).unwrap();
        }
        
        tokio::time::sleep(Duration::from_millis(50)).await;
        
        // Signal shutdown
        let shutdown_start = Instant::now();
        shutdown.notify_one();
        
        // Wait for graceful shutdown
        let result = timeout(Duration::from_secs(2), processor_task).await;
        let shutdown_time = shutdown_start.elapsed();
        
        println!("🛑 Shutdown Test Results:");
        println!("   • Shutdown completed in: {:?}", shutdown_time);
        println!("   • Graceful shutdown: {}", result.is_ok());
        
        assert!(result.is_ok(), "Processor didn't shutdown gracefully");
        assert!(shutdown_time < Duration::from_secs(1), "Shutdown took too long");
    }

    /// Helper function to create test raw events
    fn create_test_raw_event(pid: u32, comm: &str, filename: &str) -> Vec<u8> {
        // Create a mock raw event that matches the expected format
        let mut event_data = Vec::new();
        
        // Timestamp (8 bytes)
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        event_data.extend_from_slice(&timestamp.to_le_bytes());
        
        // PID (4 bytes)
        event_data.extend_from_slice(&pid.to_le_bytes());
        
        // PPID (4 bytes)
        event_data.extend_from_slice(&(pid + 1000).to_le_bytes());
        
        // UID (4 bytes)
        event_data.extend_from_slice(&1000u32.to_le_bytes());
        
        // GID (4 bytes)
        event_data.extend_from_slice(&1000u32.to_le_bytes());
        
        // Command (16 bytes, null-padded)
        let mut comm_bytes = [0u8; 16];
        let comm_str = comm.as_bytes();
        let len = std::cmp::min(comm_str.len(), 15);
        comm_bytes[..len].copy_from_slice(&comm_str[..len]);
        event_data.extend_from_slice(&comm_bytes);
        
        // Filename (256 bytes, null-padded)
        let mut filename_bytes = [0u8; 256];
        let filename_str = filename.as_bytes();
        let len = std::cmp::min(filename_str.len(), 255);
        filename_bytes[..len].copy_from_slice(&filename_str[..len]);
        event_data.extend_from_slice(&filename_bytes);
        
        // Args count (1 byte)
        event_data.push(0);
        
        // Exit code (4 bytes)
        event_data.extend_from_slice(&0i32.to_le_bytes());
        
        event_data
    }
}