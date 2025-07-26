use anyhow::Result;
use libbpf_rs::{ObjectBuilder, RingBufferBuilder};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

/// 内存事件结构（要和 memory_analyzer.bpf.c 对应！）
#[repr(C)]
#[derive(Debug)]
struct MemoryEvent {
    timestamp: u64,
    pid: u32,
    tid: u32,
    comm: [u8; 16],
    addr: u64,
    size: u64,
    access_type: u8,
    fault_type: u8,
    stack_id: u32,
    threat_score: u32,
    is_overflow: u8,
    is_leak: u8,
    violation_type: [u8; 32],
}

// 将 C 的 [u8;16] 转成 Rust String
fn cstr_to_string(buf: &[u8]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..len]).to_string()
}

fn main() -> Result<()> {
    println!("[LOAD] memory_analyzer.bpf.o ...");

    // 1️⃣ 加载 eBPF .o
    let mut obj = ObjectBuilder::default()
        .open_file("./memory_analyzer.bpf.o")?
        .load()?;

    // 2️⃣ Attach 所有 tracepoint（page_fault_user / page_fault_kernel）
    if let Some(tp) = obj.prog_mut("trace_page_fault_user") {
        tp.attach()?;
        println!("[OK] attached tracepoint exceptions/page_fault_user");
    }
    if let Some(tp) = obj.prog_mut("trace_page_fault_kernel") {
        tp.attach()?;
        println!("[OK] attached tracepoint exceptions/page_fault_kernel");
    }

    // 3️⃣ Attach kprobes（mmap、do_exit、stack_overflow_check）
    if let Some(kp) = obj.prog_mut("trace_mmap") {
        kp.attach()?;
        println!("[OK] attached kprobe do_mmap");
    }
    if let Some(kp) = obj.prog_mut("trace_process_exit") {
        kp.attach()?;
        println!("[OK] attached kprobe do_exit");
    }
    if let Some(kp) = obj.prog_mut("trace_stack_overflow") {
        kp.attach()?;
        println!("[OK] attached kprobe stack_overflow_check");
    }

    // 4️⃣ Attach malloc/free uprobe
    let libc_path = "/usr/lib/x86_64-linux-gnu/libc.so.6";
    if let Some(up) = obj.prog_mut("trace_malloc") {
        up.attach_uprobe(false, -1, libc_path, 0)?;
        println!("[OK] attached uprobe malloc");
    }
    if let Some(uret) = obj.prog_mut("trace_malloc_ret") {
        uret.attach_uprobe(true, -1, libc_path, 0)?;
        println!("[OK] attached uretprobe malloc");
    }
    if let Some(up) = obj.prog_mut("trace_free") {
        up.attach_uprobe(false, -1, libc_path, 0)?;
        println!("[OK] attached uprobe free");
    }

    // 5️⃣ RingBuffer 绑定 memory_events
    let rb_map = obj.map("memory_events").expect("ringbuf map not found");

    let mut rb_builder = RingBufferBuilder::new();

    rb_builder.add(&rb_map, |data: &[u8]| {
        if data.len() >= std::mem::size_of::<MemoryEvent>() {
            let event: &MemoryEvent = unsafe { &*(data.as_ptr() as *const MemoryEvent) };

            let comm = cstr_to_string(&event.comm);
            let vtype = cstr_to_string(&event.violation_type);

            println!(
                "[MEM-EVENT] pid={} tid={} comm={} addr=0x{:x} size={} access_type={} fault_type={} score={} overflow={} leak={} violation={}",
                event.pid,
                event.tid,
                comm,
                event.addr,
                event.size,
                event.access_type,
                event.fault_type,
                event.threat_score,
                event.is_overflow,
                event.is_leak,
                vtype
            );
        } else {
            println!("[MEM-EVENT] invalid size={}", data.len());
        }
        0
    })?;

    let rb = rb_builder.build()?;

    // Ctrl+C 优雅退出
    let running = Arc::new(AtomicBool::new(true));
    {
        let r = running.clone();
        ctrlc::set_handler(move || {
            println!("\n[CTRL+C] stopping memory analyzer...");
            r.store(false, Ordering::SeqCst);
        })?;
    }

    println!("[START] memory analyzer running... Press Ctrl+C to exit.");

    // 6️⃣ 开始轮询 ring buffer
    while running.load(Ordering::SeqCst) {
        rb.poll(Duration::from_millis(200))?;
    }

    println!("[EXIT] memory analyzer stopped.");
    Ok(())
}
