// kernel-agent/src/syscall_modifier_loader.rs

use anyhow::Result;
use libbpf_rs::{ObjectBuilder, RingBufferBuilder};
use std::{
    ffi::CStr,
    time::Duration,
    sync::{Arc, atomic::{AtomicBool, Ordering}}
};

#[repr(C)]
#[derive(Debug)]
struct SyscallEvent {
    timestamp: u64,
    pid: u32,
    uid: u32,
    gid: u32,
    comm: [u8; 16],
    syscall_nr: u32,
    original_path: [u8; 256],
    modified_path: [u8; 256],
    action_taken: u8,
    was_blocked: u8,
    threat_score: u32,
    reason: [u8; 64],
}

fn cstr_to_str(buf: &[u8]) -> String {
    if let Ok(cstr) = CStr::from_bytes_until_nul(buf) {
        cstr.to_string_lossy().into_owned()
    } else {
        // 找不到 '\0'，截断到第一个0
        let pos = buf.iter().position(|&x| x == 0).unwrap_or(buf.len());
        String::from_utf8_lossy(&buf[..pos]).to_string()
    }
}

fn main() -> Result<()> {
    println!("[LOAD] syscall_modifier.bpf.o ...");

    // 1️⃣ 加载 BPF 对象
    let mut obj = ObjectBuilder::default()
        .open_file("./syscall_modifier.bpf.o")?
        .load()?;

    // 2️⃣ 附加所有 tracepoint
    let openat = obj.prog_mut("tp_openat").unwrap();
    let _link1 = openat.attach()?;
    println!("[OK] attached sys_enter_openat");

    let execve = obj.prog_mut("tp_execve").unwrap();
    let _link2 = execve.attach()?;
    println!("[OK] attached sys_enter_execve");

    let unlink = obj.prog_mut("tp_unlink").unwrap();
    let _link3 = unlink.attach()?;
    println!("[OK] attached sys_enter_unlink");

    let chmod = obj.prog_mut("tp_chmod").unwrap();
    let _link4 = chmod.attach()?;
    println!("[OK] attached sys_enter_chmod");

    // 3️⃣ 找到 ringbuf map
    let rb_map = obj.map("syscall_events").expect("syscall_events map missing");

    // 4️⃣ 构建 ring buffer 回调
    let mut rb_builder = RingBufferBuilder::new();
    rb_builder.add(&rb_map, |data: &[u8]| {
        if data.len() < std::mem::size_of::<SyscallEvent>() {
            println!("[WARN] event size mismatch: {}", data.len());
            return 0;
        }

        let evt: &SyscallEvent = unsafe { &*(data.as_ptr() as *const SyscallEvent) };

        let comm = cstr_to_str(&evt.comm);
        let orig = cstr_to_str(&evt.original_path);
        let modp = cstr_to_str(&evt.modified_path);
        let reason = cstr_to_str(&evt.reason);

        let action = match evt.action_taken {
            0 => "ALLOW",
            1 => "DENY",
            2 => "REDIRECT",
            3 => "LOG",
            _ => "UNKNOWN",
        };

        println!(
            "[EVENT] pid={} uid={} comm={} syscall={} action={} blocked={} score={} \n  orig={} \n  mod={} \n  reason={}",
            evt.pid,
            evt.uid,
            comm,
            evt.syscall_nr,
            action,
            evt.was_blocked,
            evt.threat_score,
            orig,
            modp,
            reason
        );

        0
    })?;

    let rb = rb_builder.build()?;
    println!("[START] syscall modifier running... Ctrl+C to stop.");

    // 5️⃣ Ctrl+C 优雅退出
    let running = Arc::new(AtomicBool::new(true));
    {
        let r = running.clone();
        ctrlc::set_handler(move || {
            println!("\n[CTRL+C] Stopping...");
            r.store(false, Ordering::SeqCst);
        })?;
    }

    // 6️⃣ 阻塞轮询
    while running.load(Ordering::SeqCst) {
        rb.poll(Duration::from_millis(200))?;
    }

    Ok(())
}
