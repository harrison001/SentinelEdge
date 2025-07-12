// kernel-agent/src/events.rs
// Event structures shared between kernel and user space

use std::fmt;

/// Network connection event
#[repr(C)]
#[derive(Debug, Clone)]
pub struct EventNetConn {
    pub timestamp: u64,
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; 16],
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
}

/// Process execution event
#[repr(C)]
#[derive(Debug, Clone)]
pub struct EventExec {
    pub timestamp: u64,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: [u8; 16],
    pub filename: [u8; 256],
}

/// File operation event
#[repr(C)]
#[derive(Debug, Clone)]
pub struct EventFileOp {
    pub timestamp: u64,
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; 16],
    pub operation: u32, // 0=open, 1=read, 2=write, 3=unlink
    pub filename: [u8; 256],
    pub mode: u32,
}

/// Generic event wrapper
#[derive(Debug, Clone)]
pub enum SentinelEvent {
    NetConnection(EventNetConn),
    ProcessExecution(EventExec),
    FileOperation(EventFileOp),
}

impl fmt::Display for SentinelEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SentinelEvent::NetConnection(event) => {
                let comm = String::from_utf8_lossy(&event.comm);
                write!(f, "NET: {} (PID:{}) -> {}:{}", 
                       comm.trim_end_matches('\0'), event.pid, 
                       event.daddr, event.dport)
            }
            SentinelEvent::ProcessExecution(event) => {
                let comm = String::from_utf8_lossy(&event.comm);
                let filename = String::from_utf8_lossy(&event.filename);
                write!(f, "EXEC: {} (PID:{}) -> {}", 
                       comm.trim_end_matches('\0'), event.pid,
                       filename.trim_end_matches('\0'))
            }
            SentinelEvent::FileOperation(event) => {
                let comm = String::from_utf8_lossy(&event.comm);
                let filename = String::from_utf8_lossy(&event.filename);
                let op = match event.operation {
                    0 => "OPEN",
                    1 => "READ", 
                    2 => "WRITE",
                    3 => "UNLINK",
                    _ => "UNKNOWN"
                };
                write!(f, "FILE_{}: {} (PID:{}) -> {}", 
                       op, comm.trim_end_matches('\0'), event.pid,
                       filename.trim_end_matches('\0'))
            }
        }
    }
} 