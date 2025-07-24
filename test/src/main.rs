use anyhow::Result;
use libbpf_rs::{ObjectBuilder, MapFlags};

fn main() -> Result<()> {
    println!("[LOAD] Loading eBPF program via API...");

    let mut object = ObjectBuilder::default()
        .open_file("simple.bpf.o")?
        .load()?;

    // Get program directly and attach
    let program = object.prog_mut("trace_execve").unwrap();
    let _link = program.attach()?;
    
    println!("[OK] eBPF program loaded and attached!");

    let map = object.map("counter").unwrap();
    let key = 0u32.to_ne_bytes();
    
    println!("[CHECK] Checking initial value...");
    
    println!("[WAIT] Run some commands (like 'ls') in another terminal, then press Enter...");
    std::io::stdin().read_line(&mut String::new())?;

    if let Ok(Some(updated_value)) = map.lookup(&key, MapFlags::ANY) {
        println!("[DATA] Updated value: {:?}", updated_value);
        
        // Convert byte array to actual number
        let counter_value = u64::from_le_bytes([
            updated_value[0], updated_value[1], updated_value[2], updated_value[3],
            updated_value[4], updated_value[5], updated_value[6], updated_value[7],
        ]);
        
        println!("[COUNTER] Actual counter value: {}", counter_value);
        
        if updated_value == vec![231, 3, 0, 0, 0, 0, 0, 0] {  // 999 in little endian
            println!("[SUCCESS] eBPF program is working!");
            println!("          Counter successfully updated to 999!");
        } else if counter_value == 0 {
            println!("[ERROR] Counter unchanged! eBPF program not triggering.");
            println!("[DEBUG] Debug information:");
            println!("        - Expected value: 999");
            println!("        - Actual value: {}", counter_value);
            println!("        - Raw bytes: {:?}", updated_value);
            println!("[CAUSE] Possible causes:");
            println!("        1. eBPF program not properly attached to tracepoint");
            println!("        2. sys_enter_execve not triggered");
            println!("        3. Map update operation failed");
            println!("        4. Kernel permission or version issues");
            println!("[TIPS] Debug suggestions:");
            println!("       sudo dmesg | tail -10");
            println!("       sudo bpftool prog list");
            println!("       strace -e execve ls");
        } else {
            println!("[WARN] UNEXPECTED: Counter is {} (expected 999)", counter_value);
            println!("       This might indicate partial functionality or unexpected behavior.");
        }
    } else {
        println!("[ERROR] Failed to read map value!");
    }

    Ok(())
}