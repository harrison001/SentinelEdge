// user-agent/src/ebpf_loader.rs
// Simplified eBPF loader wrapper

use anyhow::Result;
use kernel_agent::EbpfLoader as KernelEbpfLoader;

pub struct EbpfLoader {
    inner: KernelEbpfLoader,
}

impl EbpfLoader {
    pub fn new() -> Self {
        Self {
            inner: KernelEbpfLoader::new(),
        }
    }

    pub async fn initialize(&mut self) -> Result<()> {
        self.inner.initialize().await.map_err(|e| anyhow::anyhow!(e))
    }

    pub async fn event_stream(&self) -> impl tokio_stream::Stream<Item = kernel_agent::RawEvent> {
        self.inner.event_stream().await
    }

    // TEMPORARILY DISABLED: These methods not available in simplified version
    pub async fn collect_events_batch(&self, _batch_size: usize, _max_wait: std::time::Duration) -> Vec<kernel_agent::RawEvent> {
        // self.inner.collect_events_batch(batch_size, max_wait).await
        vec![] // Temporary placeholder
    }

    pub async fn get_metrics(&self) -> kernel_agent::EbpfMetrics {
        // self.inner.get_metrics().await
        kernel_agent::EbpfMetrics::default() // Temporary placeholder
    }

    pub fn is_real_mode(&self) -> bool {
        // self.inner.is_real_mode()
        true // Temporary - simplified version is always "real"
    }

    pub async fn shutdown(self) {
        self.inner.shutdown().await
    }
} 