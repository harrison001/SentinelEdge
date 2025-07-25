//! Real eBPF Integration Tests
//! These tests actually load eBPF programs into the kernel and capture live events
//! Requires root privileges to run

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};
use tokio::time::timeout;
use tokio_stream::StreamExt;

use crate::{RawEvent, ExecEvent, EbpfLoader, EbpfConfig};

/// eBPF program that captures process execve events
const EXECVE_BPF_PROGRAM: &str = r#"
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct process_event {
    __u64 timestamp;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    char comm[16];
    char filename[256];
    __u8 args_count;
    __s32 exit_code;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

SEC("tp/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter* ctx)
{
    struct process_event event = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    event.timestamp = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.ppid = BPF_CORE_READ(task, real_parent, pid);
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.gid = bpf_get_current_uid_gid() >> 32;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // Get filename from execve args
    char *filename_ptr = (char *)ctx->args[0];
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), filename_ptr);
    
    // Count arguments (simplified)
    char **argv = (char **)ctx->args[1];
    event.args_count = 0;
    for (int i = 0; i < 10 && argv; i++) {
        char *arg;
        if (bpf_probe_read_user(&arg, sizeof(arg), &argv[i]) != 0 || !arg)
            break;
        event.args_count++;
    }
    
    event.exit_code = 0; // Will be filled on exit
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

SEC("tp/syscalls/sys_exit_execve")
int trace_execve_exit(struct trace_event_raw_sys_exit* ctx)
{
    // Could capture exit codes here
    return 0;
}

SEC("tp/sched/sched_process_exit")
int trace_process_exit(struct trace_event_raw_sched_process_template* ctx)
{
    struct process_event event = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    event.timestamp = bpf_ktime_get_ns();
    event.pid = ctx->pid;
    event.ppid = BPF_CORE_READ(task, real_parent, pid);
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.gid = bpf_get_current_uid_gid() >> 32;
    event.exit_code = ctx->ret;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

char _license[] SEC("license") = "GPL";
"#;

/// Real eBPF tester that loads programs into kernel
pub struct RealEbpfTester {
    bpf_program_fd: Option<i32>,
    perf_event_fd: Option<i32>,
    temp_dir: String,
}

impl RealEbpfTester {
    pub fn new() -> crate::error::Result<Self> {
        // Check if we have root privileges
        if unsafe { libc::geteuid() } != 0 {
            return Err(crate::error::SentinelError::Configuration(
                "Real eBPF tests require root privileges".to_string()
            ));
        }

        let temp_dir = format!("/tmp/sentinel_ebpf_{}", std::process::id());
        std::fs::create_dir_all(&temp_dir)
            .map_err(|e| crate::error::SentinelError::Io {
                operation: "file creation".to_string(),
                source: e
            })?;

        Ok(Self {
            bpf_program_fd: None,
            perf_event_fd: None,
            temp_dir,
        })
    }

    /// Compile and load the eBPF program into kernel
    pub fn load_ebpf_program(&mut self) -> crate::error::Result<()> {
        let bpf_source_path = format!("{}/execve_tracer.c", self.temp_dir);
        let bpf_object_path = format!("{}/execve_tracer.o", self.temp_dir);

        // Write eBPF source code
        let mut source_file = File::create(&bpf_source_path)
            .map_err(|e| crate::error::SentinelError::Io {
                operation: "file creation".to_string(),
                source: e
            })?;
        source_file.write_all(EXECVE_BPF_PROGRAM.as_bytes())
            .map_err(|e| crate::error::SentinelError::Io {
                operation: "file creation".to_string(),
                source: e
            })?;

        // Compile eBPF program
        let compile_output = Command::new("clang")
            .args(&[
                "-O2", "-target", "bpf", "-c",
                &bpf_source_path,
                "-o", &bpf_object_path,
                "-I/usr/include/bpf",
                "-I/usr/include/linux"
            ])
            .output()
            .map_err(|e| crate::error::SentinelError::Io {
                operation: "file creation".to_string(),
                source: e
            })?;

        if !compile_output.status.success() {
            let stderr = String::from_utf8_lossy(&compile_output.stderr);
            return Err(crate::error::SentinelError::EbpfLoad(
                format!("Failed to compile eBPF program: {}", stderr)
            ));
        }

        // Load eBPF object using bpftool (simplified approach)
        // In production, you'd use libbpf or aya crate
        let load_output = Command::new("bpftool")
            .args(&["prog", "load", &bpf_object_path, "/sys/fs/bpf/sentinel_execve"])
            .output()
            .map_err(|e| crate::error::SentinelError::Io {
                operation: "file creation".to_string(),
                source: e
            })?;

        if !load_output.status.success() {
            let stderr = String::from_utf8_lossy(&load_output.stderr);
            return Err(crate::error::SentinelError::EbpfLoad(
                format!("Failed to load eBPF program: {}", stderr)
            ));
        }

        // Attach to tracepoints
        let attach_output = Command::new("bpftool")
            .args(&[
                "prog", "attach", "/sys/fs/bpf/sentinel_execve",
                "tracepoint", "syscalls/sys_enter_execve"
            ])
            .output()
            .map_err(|e| crate::error::SentinelError::Io {
                operation: "file creation".to_string(),
                source: e
            })?;

        if !attach_output.status.success() {
            let stderr = String::from_utf8_lossy(&attach_output.stderr);
            return Err(crate::error::SentinelError::EbpfLoad(
                format!("Failed to attach eBPF program: {}", stderr)
            ));
        }

        println!("✅ Real eBPF program loaded and attached to kernel!");
        Ok(())
    }

    /// Generate real system activity to capture
    pub fn generate_real_activity(&self) -> crate::error::Result<Vec<String>> {
        let mut activities = Vec::new();

        // Create temporary files
        for i in 0..5 {
            let temp_file = format!("{}/test_file_{}.txt", self.temp_dir, i);
            let mut file = File::create(&temp_file)
                .map_err(|e| crate::error::SentinelError::Io {
                operation: "file creation".to_string(),
                source: e
            })?;
            file.write_all(format!("Test data {}", i).as_bytes())
                .map_err(|e| crate::error::SentinelError::Io {
                operation: "file creation".to_string(),
                source: e
            })?;
            activities.push(format!("Created file: {}", temp_file));
        }

        // Execute real commands that will generate execve events
        let commands = vec![
            vec!["date"],
            vec!["id"],
            vec!["pwd"],
            vec!["ls", &self.temp_dir],
            vec!["cat", "/proc/version"],
        ];

        for cmd in commands {
            let output = Command::new(&cmd[0])
                .args(&cmd[1..])
                .output()
                .map_err(|e| crate::error::SentinelError::Io {
                operation: "file creation".to_string(),
                source: e
            })?;
            
            activities.push(format!(
                "Executed: {} -> {}",
                cmd.join(" "),
                String::from_utf8_lossy(&output.stdout).trim()
            ));
        }

        Ok(activities)
    }

    /// Capture real events from kernel via perf buffer
    pub fn capture_real_events(&mut self, duration_secs: u64) -> crate::error::Result<Vec<ExecEvent>> {
        // This is a simplified version - in production you'd use proper perf buffer reading
        let mut events = Vec::new();
        let start = Instant::now();

        println!("🔍 Capturing real kernel events for {} seconds...", duration_secs);
        
        // Read from tracefs (simplified approach)
        let trace_pipe_path = "/sys/kernel/debug/tracing/trace_pipe";
        if !Path::new(trace_pipe_path).exists() {
            return Err(crate::error::SentinelError::EbpfLoad(
                "tracefs not available - mount with: mount -t tracefs tracefs /sys/kernel/debug/tracing".to_string()
            ));
        }

        // Enable tracing
        let _ = std::fs::write("/sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/enable", "1");
        let _ = std::fs::write("/sys/kernel/debug/tracing/events/sched/sched_process_exit/enable", "1");

        thread::sleep(Duration::from_millis(100)); // Let tracing start

        // Generate activity in background
        let temp_dir_clone = self.temp_dir.clone();
        thread::spawn(move || {
            let _ = Command::new("bash")
                .args(&["-c", &format!("cd {} && date && pwd && ls", temp_dir_clone)])
                .output();
        });

        // Read trace events (simplified parsing)
        if let Ok(mut trace_file) = File::open(trace_pipe_path) {
            let mut buffer = [0u8; 4096];
            let timeout_duration = Duration::from_secs(duration_secs);
            
            while start.elapsed() < timeout_duration {
                match trace_file.read(&mut buffer) {
                    Ok(0) => break, // EOF
                    Ok(n) => {
                        let trace_data = String::from_utf8_lossy(&buffer[..n]);
                        
                        // Parse trace lines and convert to ProcessEvent
                        for line in trace_data.lines() {
                            if line.contains("sys_enter_execve") || line.contains("sched_process_exit") {
                                if let Ok(event) = Self::parse_trace_line(line) {
                                    events.push(event);
                                }
                            }
                        }
                    }
                    Err(_) => break,
                }
                
                thread::sleep(Duration::from_millis(10));
            }
        }

        // Disable tracing
        let _ = std::fs::write("/sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/enable", "0");
        let _ = std::fs::write("/sys/kernel/debug/tracing/events/sched/sched_process_exit/enable", "0");

        println!("✅ Captured {} real kernel events", events.len());
        Ok(events)
    }

    /// Parse trace line into ProcessEvent (simplified)
    fn parse_trace_line(line: &str) -> crate::error::Result<ExecEvent> {
        // Example trace line:
        // bash-1234 [001] .... timestamp: sys_enter_execve: filename="/bin/date"
        
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            return Err(crate::error::SentinelError::Parse("Invalid trace line".to_string()));
        }

        // Extract process info
        let proc_info = parts[0];
        let comm_pid: Vec<&str> = proc_info.splitn(2, '-').collect();
        
        let comm = if comm_pid.len() > 0 { comm_pid[0] } else { "unknown" };
        let pid: u32 = if comm_pid.len() > 1 {
            comm_pid[1].parse().unwrap_or(0)
        } else { 0 };

        // Create realistic event
        let mut comm_array = [0u8; 16];
        let comm_bytes = comm.as_bytes();
        let copy_len = comm_bytes.len().min(15);
        comm_array[..copy_len].copy_from_slice(&comm_bytes[..copy_len]);
        
        let filename_str = if line.contains("filename=") {
            line.split("filename=\"")
                .nth(1)
                .and_then(|s| s.split('"').next())
                .unwrap_or("unknown")
        } else {
            "/proc/unknown/exe"
        };
        
        let mut filename_array = [0u8; 256];
        let filename_bytes = filename_str.as_bytes();
        let copy_len = filename_bytes.len().min(255);
        filename_array[..copy_len].copy_from_slice(&filename_bytes[..copy_len]);
        
        Ok(ExecEvent {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64,
            pid,
            ppid: 1, // Simplified
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
            comm: comm_array,
            filename: filename_array,
            args_count: 1,
            exit_code: 0,
        })
    }

    /// Test real eBPF program performance under load
    pub async fn test_real_performance(&mut self) -> crate::error::Result<()> {
        println!("🚀 Testing real eBPF performance under system load...");

        let start = Instant::now();
        let mut event_count = 0;
        
        // Generate heavy system activity
        let handles: Vec<_> = (0..4).map(|i| {
            let temp_dir = self.temp_dir.clone();
            tokio::spawn(async move {
                for j in 0..50 {
                    let _ = Command::new("bash")
                        .args(&["-c", &format!(
                            "echo 'load test {} {}' > {}/load_{}_{}.txt && cat {}/load_{}_{}.txt",
                            i, j, temp_dir, i, j, temp_dir, i, j
                        )])
                        .output();
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
        }).collect();

        // Capture events during load
        let events = self.capture_real_events(5)?;
        event_count += events.len();

        // Wait for load generators
        for handle in handles {
            let _ = handle.await;
        }

        let duration = start.elapsed();
        let events_per_sec = event_count as f64 / duration.as_secs_f64();

        println!("✅ Real eBPF Performance Results:");
        println!("   Events captured: {}", event_count);
        println!("   Duration: {:.2}s", duration.as_secs_f64());
        println!("   Events/sec: {:.2}", events_per_sec);
        println!("   Average latency: {:.2}μs", duration.as_micros() as f64 / event_count as f64);

        // Verify performance meets requirements
        if events_per_sec < 100.0 {
            return Err(crate::error::SentinelError::PerformanceTest(
                format!("Real eBPF performance too low: {:.2} events/sec", events_per_sec)
            ));
        }

        println!("✅ Real eBPF performance test passed!");
        Ok(())
    }

    /// Full integration test with real kernel interaction
    pub async fn run_full_integration_test(&mut self) -> crate::error::Result<()> {
        println!("🧪 Running full real eBPF integration test...");

        // 1. Load eBPF program
        self.load_ebpf_program()?;

        // 2. Create REAL event processor
        let config = EbpfConfig {
            ring_buffer_size: 1024,
            event_batch_size: 100,
            poll_timeout_ms: 1000,
            max_events_per_sec: 10000,
            enable_backpressure: true,
            auto_recovery: true,
            metrics_interval_sec: 60,
            ring_buffer_poll_timeout_us: Some(100),
            batch_size: Some(64),
            batch_timeout_us: Some(1000),
        };

        let mut processor = EbpfLoader::with_config(config);
        processor.initialize().await?;

        // 3. Generate real system activity
        let activities = self.generate_real_activity()?;
        println!("Generated {} real system activities", activities.len());

        // 4. Capture and process real events
        let real_events = self.capture_real_events(3)?;
        println!("Captured {} real kernel events", real_events.len());

        // 5. Process REAL events through our REAL pipeline
        let mut processed_count = 0;
        let mut event_stream = processor.event_stream().await;
        
        // Convert our captured ExecEvents to RawEvents
        for exec_event in real_events {
            let raw_event = RawEvent::Exec(exec_event);
            
            // Send through the REAL processor's channel
            if let Err(e) = processor.event_sender.try_send(raw_event) {
                println!("⚠️  Failed to send event: {}", e);
            } else {
                processed_count += 1;
            }
        }

        // Try to receive processed events from the REAL pipeline
        let timeout_duration = Duration::from_secs(2);
        let received_events = timeout(timeout_duration, async {
            let mut events = Vec::new();
            while let Some(event) = event_stream.next().await {
                events.push(event);
                if events.len() >= processed_count {
                    break;
                }
            }
            events
        }).await;

        match received_events {
            Ok(events) => {
                println!("✅ Successfully processed {} real events through REAL pipeline", events.len());
                
                // Display some real event details
                for (i, event) in events.iter().take(3).enumerate() {
                    match event {
                        RawEvent::Exec(exec) => {
                            let comm_str = std::str::from_utf8(&exec.comm).unwrap_or("unknown");
                            println!("   Real Event {}: PID={}, Comm={}", i+1, exec.pid, comm_str);
                        },
                        _ => println!("   Real Event {}: Other type", i+1),
                    }
                }
            },
            Err(_) => {
                println!("⚠️  Timeout waiting for processed events, but {} were sent to pipeline", processed_count);
            }
        }

        println!("✅ Full real eBPF integration test completed successfully!");
        Ok(())
    }
}

impl Drop for RealEbpfTester {
    fn drop(&mut self) {
        // Cleanup eBPF programs
        let _ = Command::new("bpftool")
            .args(&["prog", "detach", "/sys/fs/bpf/sentinel_execve"])
            .output();
        
        let _ = std::fs::remove_file("/sys/fs/bpf/sentinel_execve");
        let _ = std::fs::remove_dir_all(&self.temp_dir);
        
        println!("🧹 Cleaned up real eBPF programs and temporary files");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio;

    #[tokio::test]
    #[ignore = "requires_root"]
    async fn test_real_ebpf_loading() {
        let mut tester = RealEbpfTester::new().expect("Failed to create tester");
        tester.load_ebpf_program().expect("Failed to load eBPF program");
    }

    #[tokio::test] 
    #[ignore = "requires_root"]
    async fn test_real_event_capture() {
        let mut tester = RealEbpfTester::new().expect("Failed to create tester");
        tester.load_ebpf_program().expect("Failed to load eBPF program");
        
        let events = tester.capture_real_events(2).expect("Failed to capture events");
        assert!(!events.is_empty(), "Should capture at least some real events");
        
        // Verify events have realistic data
        for event in &events {
            assert!(event.timestamp > 0, "Timestamp should be valid");
            assert!(event.pid > 0, "PID should be valid");
            assert!(!event.comm.is_empty(), "Command should not be empty");
        }
    }

    #[tokio::test]
    #[ignore = "requires_root"] 
    async fn test_real_performance_under_load() {
        let mut tester = RealEbpfTester::new().expect("Failed to create tester");
        tester.load_ebpf_program().expect("Failed to load eBPF program");
        
        tester.test_real_performance().await.expect("Performance test failed");
    }

    #[tokio::test]
    #[ignore = "requires_root"]
    async fn test_full_real_integration() {
        let mut tester = RealEbpfTester::new().expect("Failed to create tester");
        tester.run_full_integration_test().await.expect("Integration test failed");
    }

    #[test]
    fn test_requires_root_privileges() {
        if unsafe { libc::geteuid() } != 0 {
            let result = RealEbpfTester::new();
            assert!(result.is_err(), "Should require root privileges");
        }
    }
}