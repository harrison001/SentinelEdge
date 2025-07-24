use anyhow::Result;
use libbpf_rs::{ObjectBuilder, MapFlags};
use std::collections::HashMap;
use std::io::{self, Write};
use std::thread;
use std::time::{Duration, Instant};

const DEBUG_STEPS: &[&str] = &[
    "🚀 函数入口时间戳",
    "📋 获取PID",
    "📊 入口计数",
    "🔍 检查主计数器",
    "✏️  更新主计数器",
    "✅ 更新结果检查",
    "🎉 成功计数",
    "🏁 函数出口时间戳",
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
        println!("\n📊 === 当前所有Map状态 ===");
        
        // 1. 主计数器
        println!("\n🎯 主计数器 (counter):");
        match self.read_map_value(&self.counter_map, 0)? {
            Some(val) => println!("   [0] = {} (0x{:x})", val, val),
            None => println!("   [0] = <不存在>"),
        }

        // 2. 调试计数器
        println!("\n🔢 调试计数器 (debug_counters):");
        for i in 0..5 {
            match self.read_map_value(&self.debug_counters_map, i)? {
                Some(val) => {
                    let desc = match i {
                        0 => "入口次数",
                        1 => "成功次数",
                        2 => "错误次数",
                        _ => "其他",
                    };
                    println!("   [{}] = {} ({})", i, val, desc);
                }
                None => println!("   [{}] = <不存在>", i),
            }
        }

        // 3. 执行轨迹
        println!("\n🔍 执行轨迹 (debug_trace):");
        for i in 0..DEBUG_STEPS.len() {
            match self.read_map_value(&self.debug_trace_map, i as u32)? {
                Some(val) => {
                    let step_desc = DEBUG_STEPS.get(i).unwrap_or(&"未知步骤");
                    
                    // 特殊处理时间戳
                    if i == 0 || i == 7 {  // 入口和出口时间戳
                        let duration_ms = val / 1_000_000;  // 纳秒转毫秒
                        println!("   [{}] = {} ({} @ {}ms)", i, val, step_desc, duration_ms);
                    } else {
                        println!("   [{}] = {} ({})", i, val, step_desc);
                    }
                }
                None => println!("   [{}] = <不存在> ({})", i, DEBUG_STEPS.get(i).unwrap_or(&"未知")),
            }
        }
        
        Ok(())
    }

    fn check_for_new_execution(&mut self) -> Result<bool> {
        // 检查入口计数器是否有变化
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
        println!("\n🔍 === 单步执行分析 ===");
        
        for (i, step_desc) in DEBUG_STEPS.iter().enumerate() {
            match self.read_map_value(&self.debug_trace_map, i as u32)? {
                Some(val) => {
                    println!("✅ 步骤 {}: {} = {}", i, step_desc, val);
                    
                    // 分析特定步骤
                    match i {
                        1 => println!("   🔍 分析: PID = {} (进程ID)", val),
                        4 => {
                            if val == 999 {
                                println!("   🎉 分析: 主计数器成功更新为999!");
                            } else {
                                println!("   ❌ 分析: 主计数器值异常: {}", val);
                            }
                        },
                        5 => {
                            if val == 1 {
                                println!("   ✅ 分析: Map更新操作成功");
                            } else {
                                println!("   ❌ 分析: Map更新操作失败");
                            }
                        },
                        0 | 7 => {
                            let duration_ms = val / 1_000_000;
                            println!("   ⏰ 分析: 时间戳 {}ms", duration_ms);
                        },
                        _ => {}
                    }
                }
                None => {
                    println!("❌ 步骤 {}: {} = <未执行>", i, step_desc);
                    if i < 3 {
                        println!("   💡 分析: eBPF程序可能未被触发或在此步骤失败");
                        break;
                    }
                }
            }
        }
        
        // 计算执行时间
        if let (Some(start), Some(end)) = 
            (self.read_map_value(&self.debug_trace_map, 0)?, 
             self.read_map_value(&self.debug_trace_map, 7)?) {
            let duration_ns = end - start;
            let duration_us = duration_ns / 1_000;
            println!("\n⏱️  总执行时间: {}ns ({}μs)", duration_ns, duration_us);
        }
        
        Ok(())
    }

    fn interactive_debugger(&mut self) -> Result<()> {
        println!("\n🐛 === 交互式调试器 ===");
        println!("命令:");
        println!("  s - 显示当前状态");
        println!("  t - 单步分析");
        println!("  w - 等待新执行");
        println!("  c - 清除调试数据");
        println!("  q - 退出");
        
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
                    println!("⏳ 等待新的eBPF执行... (Ctrl+C取消)");
                    loop {
                        if self.check_for_new_execution()? {
                            println!("🎯 检测到新的执行!");
                            self.single_step_analysis()?;
                            break;
                        }
                        thread::sleep(Duration::from_millis(100));
                    }
                }
                "c" | "clear" => {
                    println!("🧹 清除调试数据 (注意: 这只清除用户态缓存)");
                    self.last_trace_state.clear();
                }
                "q" | "quit" | "exit" => {
                    println!("👋 退出调试器");
                    break;
                }
                "" => continue,
                _ => {
                    println!("❓ 未知命令: {}", cmd);
                    println!("使用 s/t/w/c/q");
                }
            }
        }
        
        Ok(())
    }
}

fn main() -> Result<()> {
    println!("🐛 eBPF 单步调试器");
    println!("==================");

    println!("🚀 加载调试版本的eBPF程序...");
    let mut object = ObjectBuilder::default()
        .open_file("debug_simple.bpf.o")?
        .load()?;

    let program = object.prog_mut("trace_execve_debug").unwrap();
    let _link = program.attach()?;
    println!("✅ eBPF程序已加载和附加!");

    let mut debugger = eBPFDebugger::new(&object)?;

    // 初始状态
    println!("\n📊 初始状态:");
    debugger.dump_all_maps()?;

    // 等待用户触发
    println!("\n💡 现在可以:");
    println!("   1. 在另一个终端运行: ls /tmp");
    println!("   2. 或在下面的调试器中使用 'w' 命令等待");
    
    // 启动交互式调试器
    debugger.interactive_debugger()?;

    Ok(())
} 