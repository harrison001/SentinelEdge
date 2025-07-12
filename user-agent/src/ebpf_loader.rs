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
        self.inner.initialize().await
    }

    pub async fn event_stream(&self) -> impl tokio_stream::Stream<Item = kernel_agent::RawEvent> {
        self.inner.event_stream().await
    }

    pub async fn collect_events_batch(&self, batch_size: usize, max_wait: std::time::Duration) -> Vec<kernel_agent::RawEvent> {
        self.inner.collect_events_batch(batch_size, max_wait).await
    }

    pub async fn get_metrics(&self) -> kernel_agent::EbpfMetrics {
        self.inner.get_metrics().await
    }

    pub fn is_real_mode(&self) -> bool {
        self.inner.is_real_mode()
    }

    pub async fn shutdown(self) {
        self.inner.shutdown().await
    }
} 