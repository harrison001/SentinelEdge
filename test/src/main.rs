use anyhow::Result;
use libbpf_rs::{ObjectBuilder, MapFlags};

fn main() -> Result<()> {
    println!("🚀 Loading eBPF program via API...");

    let mut object = ObjectBuilder::default()
        .open_file("simple.bpf.o")?
        .load()?;

    // 直接获取程序并附加
    let program = object.prog_mut("trace_execve").unwrap();
    let _link = program.attach()?;
    
    println!("✅ eBPF program loaded and attached!");

    let map = object.map("counter").unwrap();
    let key = 0u32.to_ne_bytes();
    
    println!("📊 Checking initial value...");
    
    println!("🔄 Run some commands (like 'ls') in another terminal, then press Enter...");
    std::io::stdin().read_line(&mut String::new())?;

    if let Ok(Some(updated_value)) = map.lookup(&key, MapFlags::ANY) {
        println!("📈 Updated value: {:?}", updated_value);
        
        // 将字节数组转换为实际数字
        let counter_value = u64::from_le_bytes([
            updated_value[0], updated_value[1], updated_value[2], updated_value[3],
            updated_value[4], updated_value[5], updated_value[6], updated_value[7],
        ]);
        
        println!("📊 实际计数器值: {}", counter_value);
        
        if updated_value == vec![231, 3, 0, 0, 0, 0, 0, 0] {  // 999 in little endian
            println!("🎉 SUCCESS! eBPF program is working!");
            println!("   Counter successfully updated to 999!");
        } else if counter_value == 0 {
            println!("❌ ERROR: Counter unchanged! eBPF program not triggering.");
            println!("🔍 调试信息:");
            println!("   - 期望值: 999");
            println!("   - 实际值: {}", counter_value);
            println!("   - 原始字节: {:?}", updated_value);
            println!("🔧 可能原因:");
            println!("   1. eBPF程序未正确附加到tracepoint");
            println!("   2. sys_enter_execve未被触发");
            println!("   3. Map更新操作失败");
            println!("   4. 内核权限或版本问题");
            println!("💡 调试建议:");
            println!("   sudo dmesg | tail -10");
            println!("   sudo bpftool prog list");
            println!("   strace -e execve ls");
        } else {
            println!("⚠️  UNEXPECTED: Counter is {} (expected 999)", counter_value);
            println!("   This might indicate partial functionality or unexpected behavior.");
        }
    } else {
        println!("❌ ERROR: Failed to read map value!");
    }

    Ok(())
}