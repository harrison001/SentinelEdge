use anyhow::Result;
use libbpf_rs::{ObjectBuilder, MapFlags};
use std::collections::HashMap;
use std::io::{self, Write};
use std::thread;
use std::time::{Duration, Instant};

const DEBUG_STEPS: &[&str] = &[
    "[ENTRY] Function entry timestamp",
    "[PID] Get PID",
    "[COUNT] Entry count",
    "[CHECK] Check main counter",
    "[UPDATE] Update main counter",
    "[VERIFY] Update result check",
    "[SUCCESS] Success count",
    "[EXIT] Function exit timestamp",
];

struct eBPFDebugger {
    counter_map: libbpf_rs::Map,
    debug_counters_map: libbpf_rs::Map,
    debug_trace_map: libbpf_rs::Map,
    last_trace_state: HashMap<u32, u64>,
}

impl eBPFDebugger {
    fn new(object: &libbpf_rs::Object) -> Result<Self> {
        Ok(Self {
            counter_map: object.map("counter").unwrap(),
            debug_counters_map: object.map("debug_counters").unwrap(),
            debug_trace_map: object.map("debug_trace").unwrap(),
            last_trace_state: HashMap::new(),
        })
    }

    fn read_map_value(&self, map: &libbpf_rs::Map, key: u32) -> Result<Option<u64>> {
        let key_bytes = key.to_ne_bytes();
        match map.lookup(&key_bytes, MapFlags::ANY)? {
            Some(value_bytes) => {
                let value = u64::from_le_bytes([
                    value_bytes[0], value_bytes[1], value_bytes[2], value_bytes[3],
                    value_bytes[4], value_bytes[5], value_bytes[6], value_bytes[7],
                ]);
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }

    fn dump_all_maps(&self) -> Result<()> {
        println!("\n[STATUS] === Current All Map States ===");
        
        // 1. Main counter
        println!("\n[COUNTER] Main counter (counter):");
        match self.read_map_value(&self.counter_map, 0)? {
            Some(val) => println!("   [0] = {} (0x{:x})", val, val),
            None => println!("   [0] = <not found>"),
        }

        // 2. Debug counters
        println!("\n[DEBUG] Debug counters (debug_counters):");
        for i in 0..5 {
            match self.read_map_value(&self.debug_counters_map, i)? {
                Some(val) => {
                    let desc = match i {
                        0 => "entry count",
                        1 => "success count",
                        2 => "error count",
                        _ => "other",
                    };
                    println!("   [{}] = {} ({})", i, val, desc);
                }
                None => println!("   [{}] = <not found>", i),
            }
        }

        // 3. Execution trace
        println!("\n[TRACE] Execution trace (debug_trace):");
        for i in 0..DEBUG_STEPS.len() {
            match self.read_map_value(&self.debug_trace_map, i as u32)? {
                Some(val) => {
                    let step_desc = DEBUG_STEPS.get(i).unwrap_or(&"unknown step");
                    
                    // Special handling for timestamps
                    if i == 0 || i == 7 {  // Entry and exit timestamps
                        let duration_ms = val / 1_000_000;  // nanoseconds to milliseconds
                        println!("   [{}] = {} ({} @ {}ms)", i, val, step_desc, duration_ms);
                    } else {
                        println!("   [{}] = {} ({})", i, val, step_desc);
                    }
                }
                None => println!("   [{}] = <not found> ({})", i, DEBUG_STEPS.get(i).unwrap_or(&"unknown")),
            }
        }
        
        Ok(())
    }

    fn check_for_new_execution(&mut self) -> Result<bool> {
        // Check if entry counter has changed
        if let Some(current_count) = self.read_map_value(&self.debug_counters_map, 0)? {
            let last_count = self.last_trace_state.get(&0).unwrap_or(&0);
            if current_count > *last_count {
                self.last_trace_state.insert(0, current_count);
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn single_step_analysis(&self) -> Result<()> {
        println!("\n[ANALYSIS] === Single Step Execution Analysis ===");
        
        for (i, step_desc) in DEBUG_STEPS.iter().enumerate() {
            match self.read_map_value(&self.debug_trace_map, i as u32)? {
                Some(val) => {
                    println!("[OK] Step {}: {} = {}", i, step_desc, val);
                    
                    // Analyze specific steps
                    match i {
                        1 => println!("   [INFO] Analysis: PID = {} (Process ID)", val),
                        4 => {
                            if val == 999 {
                                println!("   [SUCCESS] Analysis: Main counter successfully updated to 999!");
                            } else {
                                println!("   [ERROR] Analysis: Main counter value abnormal: {}", val);
                            }
                        },
                        5 => {
                            if val == 1 {
                                println!("   [OK] Analysis: Map update operation successful");
                            } else {
                                println!("   [ERROR] Analysis: Map update operation failed");
                            }
                        },
                        0 | 7 => {
                            let duration_ms = val / 1_000_000;
                            println!("   [TIME] Analysis: Timestamp {}ms", duration_ms);
                        },
                        _ => {}
                    }
                }
                None => {
                    println!("[ERROR] Step {}: {} = <not executed>", i, step_desc);
                    if i < 3 {
                        println!("   [INFO] Analysis: eBPF program may not be triggered or failed at this step");
                        break;
                    }
                }
            }
        }
        
        // Calculate execution time
        if let (Some(start), Some(end)) = 
            (self.read_map_value(&self.debug_trace_map, 0)?, 
             self.read_map_value(&self.debug_trace_map, 7)?) {
            let duration_ns = end - start;
            let duration_us = duration_ns / 1_000;
            println!("\n[TIME] Total execution time: {}ns ({}μs)", duration_ns, duration_us);
        }
        
        Ok(())
    }

    fn interactive_debugger(&mut self) -> Result<()> {
        println!("\n[DEBUG] === Interactive Debugger ===");
        println!("Commands:");
        println!("  s - Show current status");
        println!("  t - Single step analysis");
        println!("  w - Wait for new execution");
        println!("  c - Clear debug data");
        println!("  q - Quit");
        
        loop {
            print!("\n(ebpf-debug) ");
            io::stdout().flush()?;
            
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let cmd = input.trim();
            
            match cmd {
                "s" | "status" => {
                    self.dump_all_maps()?;
                }
                "t" | "trace" => {
                    self.single_step_analysis()?;
                }
                "w" | "wait" => {
                    println!("[WAIT] Waiting for new eBPF execution... (Ctrl+C to cancel)");
                    loop {
                        if self.check_for_new_execution()? {
                            println!("[DETECT] New execution detected!");
                            self.single_step_analysis()?;
                            break;
                        }
                        thread::sleep(Duration::from_millis(100));
                    }
                }
                "c" | "clear" => {
                    println!("[CLEAR] Clear debug data (Note: This only clears user-space cache)");
                    self.last_trace_state.clear();
                }
                "q" | "quit" | "exit" => {
                    println!("[EXIT] Exiting debugger");
                    break;
                }
                "" => continue,
                _ => {
                    println!("[ERROR] Unknown command: {}", cmd);
                    println!("Use s/t/w/c/q");
                }
            }
        }
        
        Ok(())
    }
}

fn main() -> Result<()> {
    println!("[START] eBPF Single Step Debugger");
    println!("==================================");

    println!("[LOAD] Loading debug version eBPF program...");
    let mut object = ObjectBuilder::default()
        .open_file("debug_simple.bpf.o")?
        .load()?;

    let program = object.prog_mut("trace_execve_debug").unwrap();
    let _link = program.attach()?;
    println!("[OK] eBPF program loaded and attached!");

    let mut debugger = eBPFDebugger::new(&object)?;

    // Initial state
    println!("\n[INIT] Initial state:");
    debugger.dump_all_maps()?;

    // Wait for user trigger
    println!("\n[INFO] You can now:");
    println!("   1. Run in another terminal: ls /tmp");
    println!("   2. Or use 'w' command in debugger below to wait");
    
    // Start interactive debugger
    debugger.interactive_debugger()?;

    Ok(())
} 