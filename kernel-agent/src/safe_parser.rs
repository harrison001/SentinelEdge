// kernel-agent/src/safe_parser.rs
// Safe event parsing without unsafe operations

use crate::error::*;
use crate::events::*;
use crate::{RawEvent, ExecEvent, NetConnEvent, FileOpEvent, HeartbeatEvent, EbpfMetrics};
use std::convert::TryInto;
use tracing::{debug, warn};

/// Safe event parser that avoids unsafe memory operations
pub struct SafeEventParser {
    buffer: Vec<u8>,
    position: usize,
}

impl SafeEventParser {
    /// Create a new safe event parser
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            position: 0,
        }
    }

    /// Parse events from a byte buffer safely
    pub fn parse_events(&mut self, data: &[u8]) -> Result<Vec<RawEvent>> {
        self.buffer.clear();
        self.buffer.extend_from_slice(data);
        self.position = 0;

        let mut events = Vec::new();
        
        while self.position < self.buffer.len() {
            match self.parse_single_event() {
                Ok(Some(event)) => events.push(event),
                Ok(None) => break, // No more complete events
                Err(e) => {
                    warn!("Failed to parse event at position {}: {}", self.position, e);
                    // Skip to next potential event boundary
                    self.skip_to_next_boundary()?;
                }
            }
        }

        Ok(events)
    }

    /// Parse a single event from the current buffer position
    fn parse_single_event(&mut self) -> Result<Option<RawEvent>> {
        if self.remaining_bytes() < 4 {
            return Ok(None); // Not enough data for event type
        }

        let event_type = self.read_u32()?;
        
        match event_type {
            1 => self.parse_exec_event(),
            2 => self.parse_netconn_event(),
            3 => self.parse_fileop_event(),
            4 => self.parse_heartbeat_event(),
            _ => {
                debug!("Unknown event type: {}", event_type);
                self.skip_unknown_event()
            }
        }
    }

    /// Parse execution event safely
    fn parse_exec_event(&mut self) -> Result<Option<RawEvent>> {
        const EXEC_EVENT_SIZE: usize = 8 + 4 + 4 + 4 + 4 + 16 + 256 + 1 + 4; // timestamp + pid + ppid + uid + gid + comm + filename + args_count + exit_code
        
        if self.remaining_bytes() < EXEC_EVENT_SIZE {
            return Ok(None);
        }

        let event = ExecEvent {
            timestamp: self.read_u64()?,
            pid: self.read_u32()?,
            ppid: self.read_u32()?,
            uid: self.read_u32()?,
            gid: self.read_u32()?,
            comm: {
                let comm_bytes = self.read_fixed_string(16)?;
                let mut comm_array = [0u8; 16];
                comm_array.copy_from_slice(&comm_bytes[..16]);
                comm_array
            },
            filename: self.read_fixed_string(256)?,
            args_count: self.read_u8()?,
            exit_code: self.read_i32()?,
        };

        Ok(Some(RawEvent::Exec(event)))
    }

    /// Parse network connection event safely
    fn parse_netconn_event(&mut self) -> Result<Option<RawEvent>> {
        const NETCONN_EVENT_SIZE: usize = 8 + 4 + 4 + 16 + 4 + 4 + 2 + 2 + 1 + 1;
        
        if self.remaining_bytes() < NETCONN_EVENT_SIZE {
            return Ok(None);
        }

        let event = NetConnEvent {
            timestamp: self.read_u64()?,
            pid: self.read_u32()?,
            uid: self.read_u32()?,
            comm: {
                let comm_bytes = self.read_fixed_string(16)?;
                let mut comm_array = [0u8; 16];
                comm_array.copy_from_slice(&comm_bytes[..16]);
                comm_array
            },
            saddr: self.read_u32()?,
            daddr: self.read_u32()?,
            sport: self.read_u16()?,
            dport: self.read_u16()?,
            protocol: self.read_u8()?,
            direction: self.read_u8()?,
        };

        Ok(Some(RawEvent::NetConn(event)))
    }

    /// Parse file operation event safely
    fn parse_fileop_event(&mut self) -> Result<Option<RawEvent>> {
        const FILEOP_EVENT_SIZE: usize = 8 + 4 + 4 + 16 + 4 + 256 + 4 + 8 + 4;
        
        if self.remaining_bytes() < FILEOP_EVENT_SIZE {
            return Ok(None);
        }

        let event = FileOpEvent {
            timestamp: self.read_u64()?,
            pid: self.read_u32()?,
            uid: self.read_u32()?,
            comm: {
                let comm_bytes = self.read_fixed_string(16)?;
                let mut comm_array = [0u8; 16];
                comm_array.copy_from_slice(&comm_bytes[..16]);
                comm_array
            },
            operation: self.read_u32()?,
            filename: self.read_fixed_string(256)?,
            mode: self.read_u32()?,
            size: self.read_u64()?,
            flags: self.read_u32()?,
        };

        Ok(Some(RawEvent::FileOp(event)))
    }

    /// Parse heartbeat event safely
    fn parse_heartbeat_event(&mut self) -> Result<Option<RawEvent>> {
        const HEARTBEAT_BASE_SIZE: usize = 8 + 8; // timestamp + sequence
        const METRICS_SIZE: usize = 8 * 7 + 16; // EbpfMetrics size (approximate)
        
        if self.remaining_bytes() < HEARTBEAT_BASE_SIZE + METRICS_SIZE {
            return Ok(None);
        }

        let timestamp = self.read_u64()?;
        let sequence = self.read_u64()?;
        
        // Parse metrics
        let metrics = EbpfMetrics {
            events_processed: self.read_u64()?,
            events_dropped: self.read_u64()?,
            ring_buffer_full_count: self.read_u64()?,
            processing_errors: self.read_u64()?,
            average_latency_ns: self.read_u64()?,
            peak_events_per_sec: self.read_u64()?,
            uptime_seconds: self.read_u64()?,
            last_event_timestamp: None, // Can't safely deserialize Instant
        };

        let event = HeartbeatEvent {
            timestamp,
            sequence,
            metrics,
        };

        Ok(Some(RawEvent::Heartbeat(event)))
    }

    /// Skip unknown event type
    fn skip_unknown_event(&mut self) -> Result<Option<RawEvent>> {
        // Try to read a length field and skip that many bytes
        if self.remaining_bytes() >= 4 {
            let potential_length = self.read_u32()?;
            if potential_length <= 65536 && potential_length as usize <= self.remaining_bytes() {
                self.skip_bytes(potential_length as usize)?;
            } else {
                // Invalid length, skip to next boundary
                self.skip_to_next_boundary()?;
            }
        }
        Ok(None)
    }

    /// Skip to the next event boundary (basic heuristic)
    fn skip_to_next_boundary(&mut self) -> Result<()> {
        // Look for what might be a valid event type (1, 2, 3, or 4)
        while self.position < self.buffer.len().saturating_sub(4) {
            let potential_type = u32::from_ne_bytes([
                self.buffer[self.position],
                self.buffer[self.position + 1],
                self.buffer[self.position + 2],
                self.buffer[self.position + 3],
            ]);
            
            if matches!(potential_type, 1..=4) {
                break;
            }
            
            self.position += 1;
        }
        Ok(())
    }

    /// Read a u8 from the buffer
    fn read_u8(&mut self) -> Result<u8> {
        if self.position >= self.buffer.len() {
            return Err(SentinelError::EventProcessing {
                message: "Buffer underrun reading u8".to_string(),
                event_type: "unknown".to_string(),
            });
        }
        
        let value = self.buffer[self.position];
        self.position += 1;
        Ok(value)
    }

    /// Read a u16 from the buffer
    fn read_u16(&mut self) -> Result<u16> {
        if self.position + 2 > self.buffer.len() {
            return Err(SentinelError::EventProcessing {
                message: "Buffer underrun reading u16".to_string(),
                event_type: "unknown".to_string(),
            });
        }
        
        let bytes = [self.buffer[self.position], self.buffer[self.position + 1]];
        let value = u16::from_ne_bytes(bytes);
        self.position += 2;
        Ok(value)
    }

    /// Read a u32 from the buffer
    fn read_u32(&mut self) -> Result<u32> {
        if self.position + 4 > self.buffer.len() {
            return Err(SentinelError::EventProcessing {
                message: "Buffer underrun reading u32".to_string(),
                event_type: "unknown".to_string(),
            });
        }
        
        let bytes = [
            self.buffer[self.position],
            self.buffer[self.position + 1],
            self.buffer[self.position + 2],
            self.buffer[self.position + 3],
        ];
        let value = u32::from_ne_bytes(bytes);
        self.position += 4;
        Ok(value)
    }

    /// Read a u64 from the buffer
    fn read_u64(&mut self) -> Result<u64> {
        if self.position + 8 > self.buffer.len() {
            return Err(SentinelError::EventProcessing {
                message: "Buffer underrun reading u64".to_string(),
                event_type: "unknown".to_string(),
            });
        }
        
        let bytes = [
            self.buffer[self.position],
            self.buffer[self.position + 1],
            self.buffer[self.position + 2],
            self.buffer[self.position + 3],
            self.buffer[self.position + 4],
            self.buffer[self.position + 5],
            self.buffer[self.position + 6],
            self.buffer[self.position + 7],
        ];
        let value = u64::from_ne_bytes(bytes);
        self.position += 8;
        Ok(value)
    }

    /// Read an i32 from the buffer
    fn read_i32(&mut self) -> Result<i32> {
        if self.position + 4 > self.buffer.len() {
            return Err(SentinelError::EventProcessing {
                message: "Buffer underrun reading i32".to_string(),
                event_type: "unknown".to_string(),
            });
        }
        
        let bytes = [
            self.buffer[self.position],
            self.buffer[self.position + 1],
            self.buffer[self.position + 2],
            self.buffer[self.position + 3],
        ];
        let value = i32::from_ne_bytes(bytes);
        self.position += 4;
        Ok(value)
    }

    /// Read a fixed-size string from the buffer
    fn read_fixed_string(&mut self, size: usize) -> Result<[u8; 256]> {
        if size > 256 {
            return Err(SentinelError::EventProcessing {
                message: format!("String size {} exceeds maximum of 256", size),
                event_type: "unknown".to_string(),
            });
        }

        if self.position + size > self.buffer.len() {
            return Err(SentinelError::EventProcessing {
                message: format!("Buffer underrun reading string of size {}", size),
                event_type: "unknown".to_string(),
            });
        }

        let mut result = [0u8; 256];
        let end_pos = (self.position + size).min(self.buffer.len());
        let actual_size = end_pos - self.position;
        
        result[..actual_size].copy_from_slice(&self.buffer[self.position..end_pos]);
        self.position += size; // Always advance by requested size
        
        Ok(result)
    }

    /// Skip a number of bytes
    fn skip_bytes(&mut self, count: usize) -> Result<()> {
        if self.position + count > self.buffer.len() {
            return Err(SentinelError::EventProcessing {
                message: format!("Cannot skip {} bytes, would exceed buffer", count),
                event_type: "unknown".to_string(),
            });
        }
        
        self.position += count;
        Ok(())
    }

    /// Get remaining bytes in buffer
    fn remaining_bytes(&self) -> usize {
        self.buffer.len().saturating_sub(self.position)
    }
}

impl Default for SafeEventParser {
    fn default() -> Self {
        Self::new()
    }
}

/// Utility function to safely convert byte array to string
pub fn safe_cstr_to_string(bytes: &[u8]) -> String {
    // Find the first null byte or use the entire slice
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    
    // Convert to string, replacing invalid UTF-8 with replacement characters
    String::from_utf8_lossy(&bytes[..end]).to_string()
}

/// Validate event data integrity
pub fn validate_event_data(event: &RawEvent) -> Result<()> {
    match event {
        RawEvent::Exec(e) => {
            if e.timestamp == 0 {
                return Err(SentinelError::EventProcessing {
                    message: "Invalid timestamp: 0".to_string(),
                    event_type: "exec".to_string(),
                });
            }
            if e.pid == 0 && e.ppid == 0 {
                return Err(SentinelError::EventProcessing {
                    message: "Invalid process IDs: both pid and ppid are 0".to_string(),
                    event_type: "exec".to_string(),
                });
            }
        }
        RawEvent::NetConn(e) => {
            if e.timestamp == 0 {
                return Err(SentinelError::EventProcessing {
                    message: "Invalid timestamp: 0".to_string(),
                    event_type: "netconn".to_string(),
                });
            }
            if e.sport == 0 && e.dport == 0 {
                return Err(SentinelError::EventProcessing {
                    message: "Invalid ports: both source and destination are 0".to_string(),
                    event_type: "netconn".to_string(),
                });
            }
        }
        RawEvent::FileOp(e) => {
            if e.timestamp == 0 {
                return Err(SentinelError::EventProcessing {
                    message: "Invalid timestamp: 0".to_string(),
                    event_type: "fileop".to_string(),
                });
            }
        }
        RawEvent::Heartbeat(e) => {
            if e.timestamp == 0 {
                return Err(SentinelError::EventProcessing {
                    message: "Invalid timestamp: 0".to_string(),
                    event_type: "heartbeat".to_string(),
                });
            }
        }
        RawEvent::Error(_) => {
            // Error events are always valid
        }
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_string_conversion() {
        let bytes_with_null = b"hello\0world";
        let result = safe_cstr_to_string(bytes_with_null);
        assert_eq!(result, "hello");

        let bytes_without_null = b"hello";
        let result = safe_cstr_to_string(bytes_without_null);
        assert_eq!(result, "hello");

        let invalid_utf8 = &[0xFF, 0xFE, b'h', b'i'];
        let result = safe_cstr_to_string(invalid_utf8);
        assert!(result.contains('h')); // Should contain valid parts
    }

    #[test]
    fn test_event_validation() {
        let valid_exec = ExecEvent {
            timestamp: 1234567890,
            pid: 1000,
            ppid: 999,
            uid: 1000,
            gid: 1000,
            comm: [0; 16],
            filename: [0; 256],
            args_count: 1,
            exit_code: 0,
        };
        
        let result = validate_event_data(&RawEvent::Exec(valid_exec));
        assert!(result.is_ok());

        let invalid_exec = ExecEvent {
            timestamp: 0, // Invalid
            pid: 0,
            ppid: 0,
            uid: 1000,
            gid: 1000,
            comm: [0; 16],
            filename: [0; 256],
            args_count: 1,
            exit_code: 0,
        };
        
        let result = validate_event_data(&RawEvent::Exec(invalid_exec));
        assert!(result.is_err());
    }

    #[test]
    fn test_buffer_underrun_protection() {
        let mut parser = SafeEventParser::new();
        
        // Test with insufficient data
        let small_buffer = &[1, 2, 3]; // Not enough for any event
        let result = parser.parse_events(small_buffer);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_invalid_event_type_handling() {
        let mut parser = SafeEventParser::new();
        
        // Buffer with invalid event type
        let mut buffer = vec![255, 255, 255, 255]; // Invalid event type
        buffer.extend_from_slice(&[0; 100]); // Padding
        
        let result = parser.parse_events(&buffer);
        assert!(result.is_ok());
        // Should handle gracefully without panicking
    }
}