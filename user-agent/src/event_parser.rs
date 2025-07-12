// user-agent/src/event_parser.rs
// Event parsing and transformation

use anyhow::Result;
use kernel_agent::RawEvent;
use crate::rule_engine::ParsedEvent;

pub struct EventParser;

impl EventParser {
    pub fn new() -> Self {
        Self
    }

    pub fn parse(&self, raw_event: RawEvent) -> Result<ParsedEvent> {
        match raw_event {
            RawEvent::Exec(exec_event) => {
                let process_name = String::from_utf8_lossy(&exec_event.comm).to_string();
                let file_path = String::from_utf8_lossy(&exec_event.filename).to_string();
                
                Ok(ParsedEvent {
                    event_type: "process_execution".to_string(),
                    process_name,
                    file_path,
                    pid: exec_event.pid,
                    timestamp: exec_event.timestamp,
                })
            }
            RawEvent::FileOp(file_event) => {
                let process_name = String::from_utf8_lossy(&file_event.comm).to_string();
                let file_path = String::from_utf8_lossy(&file_event.filename).to_string();
                
                Ok(ParsedEvent {
                    event_type: "file_operation".to_string(),
                    process_name,
                    file_path,
                    pid: file_event.pid,
                    timestamp: file_event.timestamp,
                })
            }
            RawEvent::NetConn(net_event) => {
                let process_name = String::from_utf8_lossy(&net_event.comm).to_string();
                
                Ok(ParsedEvent {
                    event_type: "network_connection".to_string(),
                    process_name,
                    file_path: format!("{}:{} -> {}:{}", 
                        self.ip_to_string(net_event.saddr),
                        net_event.sport,
                        self.ip_to_string(net_event.daddr),
                        net_event.dport
                    ),
                    pid: net_event.pid,
                    timestamp: net_event.timestamp,
                })
            }
            RawEvent::Error(error_event) => {
                Ok(ParsedEvent {
                    event_type: "error".to_string(),
                    process_name: "unknown".to_string(),
                    file_path: error_event.message,
                    pid: 0,
                    timestamp: error_event.timestamp,
                })
            }
            RawEvent::Heartbeat(heartbeat_event) => {
                Ok(ParsedEvent {
                    event_type: "heartbeat".to_string(),
                    process_name: "system".to_string(),
                    file_path: "heartbeat".to_string(),
                    pid: 0,
                    timestamp: heartbeat_event.timestamp,
                })
            }
        }
    }

    fn ip_to_string(&self, ip: u32) -> String {
        format!("{}.{}.{}.{}",
            (ip & 0xFF),
            (ip >> 8) & 0xFF,
            (ip >> 16) & 0xFF,
            (ip >> 24) & 0xFF
        )
    }
} 