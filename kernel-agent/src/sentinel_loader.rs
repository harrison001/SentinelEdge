use anyhow::Result;
use libbpf_rs::{ObjectBuilder, RingBufferBuilder};
use std::mem::size_of;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

// ✅ Rust 对应 eBPF 的结构 (repr(C))
#[repr(C)]
#[derive(Debug)]
struct EventExec {
    timestamp: u64,
    pid: u32,
    ppid: u32,
    uid: u32,
    gid: u32,
    comm: [u8; 16],
    filename: [u8; 256],
}

#[repr(C)]
#[derive(Debug)]
struct EventNetConn {
    timestamp: u64,
    pid: u32,
    uid: u32,
    comm: [u8; 16],
    saddr: u32,
    daddr: u32,
    sport: u16,
    dport: u16,
}

#[repr(C)]
#[derive(Debug)]
struct EventFileOp {
    timestamp: u64,
    pid: u32,
    uid: u32,
    comm: [u8; 16],
    operation: u32,
    filename: [u8; 256],
    mode: u32,
}

// ✅ 把 C 的 char[] 转成 Rust &str
fn to_string(bytes: &[u8]) -> String {
    let len = bytes.iter().position(|&c| c == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..len]).to_string()
}

fn main() -> Result<()> {
    println!("[LOAD] Loading sentinel.bpf.o ...");

    // ✅ 1) 打开并加载 sentinel.bpf.o
    let mut obj = ObjectBuilder::default()
        .open_file("./sentinel.bpf.o")?
        .load()?;

    // ✅ 2) attach 三个程序
    let prog_exec = obj.prog_mut("trace_execve").unwrap();
    let _exec_link = prog_exec.attach()?;

    let prog_tcp = obj.prog_mut("trace_tcp_connect").unwrap();
    let _tcp_link = prog_tcp.attach()?;

    let prog_file = obj.prog_mut("trace_file_open").unwrap();
    let _file_link = prog_file.attach()?;

    println!("[OK] Attached execve + tcp_connect + vfs_open!");

    // ✅ 3) 找到 ring buffer
    let rb_map = obj.map("rb").expect("❌ ring buffer map not found");

    // ✅ 4) 事件计数
    let running = Arc::new(AtomicBool::new(true));
    let running_ctrlc = running.clone();

    // ✅ Ctrl+C 优雅退出
    ctrlc::set_handler(move || {
        println!("\n[CTRL+C] Stopping monitor...");
        running_ctrlc.store(false, Ordering::SeqCst);
    })?;

    // ✅ 5) 注册回调
    let mut rb_builder = RingBufferBuilder::new();
    rb_builder.add(&rb_map, |data: &[u8]| {
        let len = data.len();

        if len == size_of::<EventExec>() {
            let e: &EventExec = unsafe { &*(data.as_ptr() as *const EventExec) };
            println!(
                "[EXEC] pid={} ppid={} uid={} comm={} file={}",
                e.pid,
                e.ppid,
                e.uid,
                to_string(&e.comm),
                to_string(&e.filename)
            );
        } else if len == size_of::<EventNetConn>() {
            let e: &EventNetConn = unsafe { &*(data.as_ptr() as *const EventNetConn) };
            println!(
                "[TCP] pid={} uid={} comm={} {}:{} -> {}:{}",
                e.pid,
                e.uid,
                to_string(&e.comm),
                u32::from_be(e.saddr),
                e.sport,
                u32::from_be(e.daddr),
                e.dport
            );
        } else if len == size_of::<EventFileOp>() {
            let e: &EventFileOp = unsafe { &*(data.as_ptr() as *const EventFileOp) };
            println!(
                "[FILE] pid={} uid={} comm={} op={} file={}",
                e.pid,
                e.uid,
                to_string(&e.comm),
                e.operation,
                to_string(&e.filename)
            );
        } else {
            println!("[UNKNOWN EVENT] {} bytes", len);
        }
        0
    })?;

    let rb = rb_builder.build()?;

    println!("[START] Monitoring... Press Ctrl+C to exit.");
    while running.load(Ordering::SeqCst) {
        rb.poll(Duration::from_millis(200))?;
    }

    println!("[EXIT] sentinel_loader done.");
    Ok(())
}
