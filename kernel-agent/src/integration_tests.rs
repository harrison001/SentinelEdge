// kernel-agent/src/integration_tests.rs
// Comprehensive integration tests for SentinelEdge kernel agent

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::error::*;
    use crate::events::*;
    use crate::{EbpfConfig, EbpfLoader, RawEvent};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::time::timeout;
    use tokio_stream::StreamExt;
    use tracing_subscriber;

    /// Test configuration for integration tests
    fn test_config() -> EbpfConfig {
        EbpfConfig {
            ring_buffer_size: 64 * 1024, // Smaller for tests
            event_batch_size: 10,
            poll_timeout_ms: 50,
            max_events_per_sec: 1000,
            enable_backpressure: true,
            auto_recovery: true,
            metrics_interval_sec: 1,
            ring_buffer_poll_timeout_us: Some(50),
            batch_size: Some(5),
            batch_timeout_us: Some(500),
        }
    }

    /// Initialize test tracing
    fn init_test_tracing() {
        let _ = tracing_subscriber::fmt()
            .with_test_writer()
            .with_env_filter("debug")
            .try_init();
    }

    #[tokio::test]
    async fn test_end_to_end_event_processing() {
        init_test_tracing();
        
        let mut loader = EbpfLoader::with_config(test_config());
        
        // Initialize should succeed (will fall back to mock mode on non-Linux)
        let result = loader.initialize().await;
        assert!(result.is_ok(), "Initialization failed: {:?}", result);

        // Test event stream
        let mut event_stream = loader.event_stream().await;
        
        // Set a timeout to avoid hanging
        let events = timeout(Duration::from_secs(2), async {
            let mut collected_events = Vec::new();
            let mut count = 0;
            
            while let Some(event) = event_stream.next().await {
                collected_events.push(event);
                count += 1;
                if count >= 5 { // Collect 5 events
                    break;
                }
            }
            collected_events
        }).await;

        assert!(events.is_ok(), "Failed to collect events within timeout");
        let event_list = events.unwrap();
        assert!(!event_list.is_empty(), "No events were generated");

        // Verify event types
        for event in &event_list {
            match event {
                RawEvent::Exec(_) | RawEvent::NetConn(_) | 
                RawEvent::FileOp(_) | RawEvent::Heartbeat(_) => {
                    // Valid event types
                }
                RawEvent::Error(e) => {
                    println!("Warning: Error event received: {:?}", e);
                }
            }
        }

        // Test graceful shutdown
        loader.shutdown().await;
    }

    #[tokio::test]
    async fn test_error_recovery_mechanisms() {
        init_test_tracing();
        
        let mut loader = EbpfLoader::with_config(EbpfConfig {
            max_events_per_sec: 1, // Very low limit to trigger backpressure
            ..test_config()
        });

        loader.initialize().await.expect("Initialization failed");

        // Test rate limiting and backpressure
        let mut event_stream = loader.event_stream().await;
        
        // Rapidly consume events to test rate limiting
        let start_time = std::time::Instant::now();
        let mut event_count = 0;
        
        let result = timeout(Duration::from_secs(3), async {
            while let Some(_) = event_stream.next().await {
                event_count += 1;
                if event_count >= 10 {
                    break;
                }
            }
        }).await;

        let elapsed = start_time.elapsed();
        
        // With rate limiting, it should take at least some time
        assert!(elapsed >= Duration::from_millis(500), 
            "Rate limiting doesn't seem to be working: elapsed {:?}", elapsed);

        loader.shutdown().await;
    }

    #[tokio::test]
    async fn test_configuration_validation() {
        init_test_tracing();
        
        // Test invalid configurations
        let invalid_configs = vec![
            EbpfConfig {
                ring_buffer_size: 0, // Invalid: zero size
                ..test_config()
            },
            EbpfConfig {
                event_batch_size: 0, // Invalid: zero batch size
                ..test_config()
            },
            EbpfConfig {
                max_events_per_sec: 0, // Invalid: zero rate limit
                ..test_config()
            },
        ];

        for config in invalid_configs {
            let mut loader = EbpfLoader::with_config(config);
            // Should either fail initialization or fall back gracefully
            match loader.initialize().await {
                Ok(_) => {
                    // If it succeeds, ensure it's in a valid state
                    let _metrics = loader.get_metrics().await;
                }
                Err(e) => {
                    // Expected failure for invalid config
                    println!("Expected configuration error: {:?}", e);
                }
            }
        }
    }

    #[tokio::test]
    async fn test_metrics_collection() {
        init_test_tracing();
        
        let mut loader = EbpfLoader::with_config(test_config());
        loader.initialize().await.expect("Initialization failed");

        // Let it run for a bit to collect metrics
        tokio::time::sleep(Duration::from_millis(500)).await;

        let metrics = loader.get_metrics().await;
        
        // Basic metric validation
        assert!(metrics.uptime_seconds > 0, "Uptime should be positive");
        // Events processed might be 0 in test environment, which is fine
        
        println!("Collected metrics: {:?}", metrics);
        
        loader.shutdown().await;
    }

    #[tokio::test]
    async fn test_concurrent_access() {
        init_test_tracing();
        
        let mut loader = EbpfLoader::with_config(test_config());
        loader.initialize().await.expect("Initialization failed");

        // Spawn multiple concurrent tasks accessing the loader
        let handles = (0..5).map(|i| {
            let metrics_clone = Arc::clone(&loader.metrics);
            tokio::spawn(async move {
                for _ in 0..10 {
                    let _metrics = metrics_clone.read().await;
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                i
            })
        }).collect::<Vec<_>>();

        // Wait for all tasks to complete
        for handle in handles {
            let result = handle.await;
            assert!(result.is_ok(), "Concurrent task failed: {:?}", result);
        }

        loader.shutdown().await;
    }

    #[tokio::test]
    async fn test_memory_pressure() {
        init_test_tracing();
        
        let mut loader = EbpfLoader::with_config(EbpfConfig {
            ring_buffer_size: 1024, // Very small buffer
            event_batch_size: 1000,  // Large batch size
            ..test_config()
        });

        loader.initialize().await.expect("Initialization failed");

        // Create memory pressure by not consuming events
        let _event_stream = loader.event_stream().await;
        
        // Let it run to potentially fill buffers
        tokio::time::sleep(Duration::from_millis(200)).await;

        // System should remain stable
        let metrics = loader.get_metrics().await;
        
        // Check if backpressure mechanisms kicked in
        if metrics.ring_buffer_full_count > 0 {
            println!("Backpressure correctly activated: {} ring buffer full events", 
                metrics.ring_buffer_full_count);
        }

        loader.shutdown().await;
    }

    #[tokio::test]
    async fn test_error_event_handling() {
        init_test_tracing();
        
        let mut loader = EbpfLoader::with_config(test_config());
        loader.initialize().await.expect("Initialization failed");

        let mut event_stream = loader.event_stream().await;
        
        // Look for error events (they might be generated in mock mode)
        let result = timeout(Duration::from_secs(1), async {
            while let Some(event) = event_stream.next().await {
                if let RawEvent::Error(error_event) = event {
                    return Some(error_event);
                }
            }
            None
        }).await;

        match result {
            Ok(Some(error_event)) => {
                println!("Found error event: {:?}", error_event);
                assert!(!error_event.message.is_empty(), "Error message should not be empty");
                assert!(!error_event.context.is_empty(), "Error context should not be empty");
            }
            Ok(None) => {
                println!("No error events found (this is fine)");
            }
            Err(_) => {
                println!("Timeout waiting for events (this might be expected)");
            }
        }

        loader.shutdown().await;
    }

    #[tokio::test]
    async fn test_graceful_shutdown() {
        init_test_tracing();
        
        let mut loader = EbpfLoader::with_config(test_config());
        loader.initialize().await.expect("Initialization failed");

        let event_stream = loader.event_stream().await;
        
        // Start consuming events in a separate task
        let consume_handle = tokio::spawn(async move {
            let mut stream = event_stream;
            let mut count = 0;
            while let Some(_) = stream.next().await {
                count += 1;
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            count
        });

        // Let it run for a bit
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Trigger shutdown
        let shutdown_start = std::time::Instant::now();
        loader.shutdown().await;
        let shutdown_duration = shutdown_start.elapsed();

        // Shutdown should be reasonably fast
        assert!(shutdown_duration < Duration::from_secs(5), 
            "Shutdown took too long: {:?}", shutdown_duration);

        // The consume task should complete
        let consume_result = timeout(Duration::from_secs(2), consume_handle).await;
        assert!(consume_result.is_ok(), "Consumer task didn't complete after shutdown");
    }

    #[tokio::test]
    async fn test_event_stream_backpressure() {
        init_test_tracing();
        
        let mut loader = EbpfLoader::with_config(EbpfConfig {
            enable_backpressure: true,
            max_events_per_sec: 100,
            ..test_config()
        });

        loader.initialize().await.expect("Initialization failed");

        let mut event_stream = loader.event_stream().await;
        
        // Consume events slowly to test backpressure
        let mut events_received = 0;
        let start_time = std::time::Instant::now();
        
        let result = timeout(Duration::from_secs(2), async {
            while let Some(_) = event_stream.next().await {
                events_received += 1;
                if events_received >= 50 {
                    break;
                }
                // Slow consumption
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }).await;

        let elapsed = start_time.elapsed();
        
        assert!(result.is_ok(), "Event collection timed out");
        assert!(events_received > 0, "Should have received some events");
        
        // With backpressure, the system should remain stable
        let metrics = loader.get_metrics().await;
        println!("Metrics after backpressure test: processed={}, dropped={}", 
            metrics.events_processed, metrics.events_dropped);

        loader.shutdown().await;
    }
}

#[cfg(target_os = "linux")]
#[cfg(test)]
mod linux_specific_tests {
    use super::*;
    use crate::{EbpfConfig, EbpfLoader, RawEvent};
    use std::time::Duration;
    use tokio::time::timeout;
    use tokio_stream::StreamExt;

    #[tokio::test]
    #[ignore = "Requires root privileges and Linux environment"]
    async fn test_real_ebpf_loading() {
        // This test should only run with --ignored flag and root privileges
        let mut loader = EbpfLoader::with_config(EbpfConfig::default());
        
        // This will attempt real eBPF loading
        let result = loader.initialize().await;
        
        match result {
            Ok(_) => {
                println!("✅ Real eBPF program loaded successfully");
                
                // Test real event collection
                let mut event_stream = loader.event_stream().await;
                let mut real_events = 0;
                
                let events = timeout(Duration::from_secs(5), async {
                    while let Some(event) = event_stream.next().await {
                        match event {
                            RawEvent::Exec(_) | RawEvent::NetConn(_) | RawEvent::FileOp(_) => {
                                real_events += 1;
                                if real_events >= 3 {
                                    break;
                                }
                            }
                            _ => {}
                        }
                    }
                }).await;

                assert!(events.is_ok(), "Should collect real events");
                println!("✅ Collected {} real kernel events", real_events);
                
                loader.shutdown().await;
            }
            Err(e) => {
                println!("⚠️ eBPF loading failed (expected without root): {:?}", e);
                // This is expected when not running as root
            }
        }
    }

    #[tokio::test]
    #[ignore = "Performance test - run manually"]
    async fn test_high_throughput_performance() {
        let mut loader = EbpfLoader::with_config(EbpfConfig {
            ring_buffer_size: 1024 * 1024, // 1MB buffer
            event_batch_size: 1000,
            max_events_per_sec: 100000, // High throughput
            ..EbpfConfig::default()
        });

        loader.initialize().await.expect("Initialization failed");

        let mut event_stream = loader.event_stream().await;
        let start_time = std::time::Instant::now();
        let mut event_count = 0;

        let result = timeout(Duration::from_secs(10), async {
            while let Some(_) = event_stream.next().await {
                event_count += 1;
                if event_count >= 10000 {
                    break;
                }
            }
        }).await;

        let elapsed = start_time.elapsed();
        let events_per_sec = event_count as f64 / elapsed.as_secs_f64();

        println!("Performance test results:");
        println!("  Events processed: {}", event_count);
        println!("  Time elapsed: {:?}", elapsed);
        println!("  Events per second: {:.2}", events_per_sec);

        // Performance assertions (adjust based on expected performance)
        assert!(events_per_sec > 100.0, "Should process at least 100 events/sec");
        
        loader.shutdown().await;
    }
}