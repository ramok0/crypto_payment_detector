use crate::error::DetectorError;
use crate::types::DetectedPayment;

pub trait PaymentDetector: Send + Sync {
    fn derive_address(&self, index: u32) -> Result<String, DetectorError>;

    fn scan_block(
        &self,
        block_height: u64,
        max_derivation_index: u32,
    ) -> impl std::future::Future<Output = Result<Vec<DetectedPayment>, DetectorError>> + Send;

    fn run_block_scan_loop(
        &self,
        start_height: Option<u64>,
        max_derivation_index: u32,
    ) -> impl std::future::Future<Output = Result<(), DetectorError>> + Send;
}
