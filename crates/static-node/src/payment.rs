//! Cryptocurrency payment support for compute requests
//!
//! Supports Monero (XMR), Darkfi (DARK), and Navio (NAV).
//! All payments are prepayment: the requester pays before execution.
//! The provider generates a new receive address per request and watches
//! the blockchain via a daemon RPC for incoming payments. Static never
//! sends payments itself — the on-chain transaction happens in the
//! user's own wallet, outside the network.
//!
//! The wire types ([`Currency`], [`PaymentRequest`],
//! [`PaymentConfirmation`]) live in `static-storage::compute` next to the
//! other Sphinx-body messages and are re-exported here.

use async_trait::async_trait;

// Wire types are Sphinx-body messages defined next to ComputeRequest /
// ComputeResponse; re-exported here so payment code has a single import site.
pub use static_storage::compute::{Currency, PaymentConfirmation, PaymentRequest};

/// Provider's pricing for compute
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ComputePricing {
    /// Price per execution in atomic units (smallest denomination)
    /// 0 = free (provider doesn't charge)
    pub price_per_execution: u64,
    /// Price per CPU second in atomic units
    pub price_per_cpu_sec: u64,
    /// Price per MB of memory used in atomic units
    pub price_per_mb: u64,
    /// Accepted currencies
    pub accepted_currencies: Vec<Currency>,
    /// Number of confirmations required before execution
    pub required_confirmations: u32,
}

impl Default for ComputePricing {
    fn default() -> Self {
        Self {
            price_per_execution: 0,
            price_per_cpu_sec: 0,
            price_per_mb: 0,
            accepted_currencies: vec![Currency::Monero],
            required_confirmations: 1,
        }
    }
}

impl ComputePricing {
    /// Whether this provider offers free compute (all rates zero)
    ///
    /// Free-tier providers execute immediately with no payment round-trip.
    pub fn is_free(&self) -> bool {
        self.price_per_execution == 0
            && self.price_per_cpu_sec == 0
            && self.price_per_mb == 0
    }

    /// Whether the given currency is accepted
    pub fn accepts(&self, currency: Currency) -> bool {
        self.accepted_currencies.contains(&currency)
    }

    /// Worst-case prepayment amount in atomic units
    ///
    /// Quoted before execution, so the CPU-second and memory terms use the
    /// provider's configured execution caps (`max_cpu_ms`, `max_memory_mb`).
    pub fn amount_due(&self, max_cpu_ms: u64, max_memory_mb: u64) -> u64 {
        let cpu_secs = max_cpu_ms.div_ceil(1000);
        self.price_per_execution
            .saturating_add(self.price_per_cpu_sec.saturating_mul(cpu_secs))
            .saturating_add(self.price_per_mb.saturating_mul(max_memory_mb))
    }
}

/// Payment state for a single compute request (provider side)
#[derive(Debug, Clone)]
pub enum PaymentState {
    /// Waiting for requester to pay
    AwaitingPayment {
        /// The payment request sent to the requester
        request: PaymentRequest,
        /// When the payment request was sent
        sent_at: u64,
    },
    /// Payment confirmed on blockchain, executing
    PaymentConfirmed {
        /// The transaction hash
        tx_hash: String,
        /// When payment was confirmed
        confirmed_at: u64,
    },
    /// Payment timed out (requester didn't pay in time)
    PaymentTimeout,
}

/// Configuration for blockchain watching
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlockchainConfig {
    /// Monero wallet RPC URL (e.g., http://127.0.0.1:18082/json_rpc;
    /// `monero-wallet-rpc`, not `monerod` — address creation needs a wallet)
    pub monero_rpc_url: String,
    /// Darkfi daemon RPC URL
    pub darkfi_rpc_url: String,
    /// Navio daemon RPC URL
    pub navio_rpc_url: String,
    /// Payment timeout in seconds (default: 3600 = 1 hour)
    pub payment_timeout_secs: u64,
}

impl Default for BlockchainConfig {
    fn default() -> Self {
        Self {
            monero_rpc_url: "http://127.0.0.1:18082/json_rpc".to_string(),
            darkfi_rpc_url: "http://127.0.0.1:8269".to_string(),
            navio_rpc_url: "http://127.0.0.1:38888".to_string(),
            payment_timeout_secs: 3600,
        }
    }
}

/// Errors that can occur during payment operations
#[derive(Debug, thiserror::Error)]
pub enum PaymentError {
    /// RPC call to the cryptocurrency daemon failed
    #[error("RPC error: {0}")]
    RpcError(String),
    /// Address generation failed
    #[error("address generation failed: {0}")]
    AddressGenerationFailed(String),
    /// Payment not found
    #[error("payment not found")]
    PaymentNotFound,
    /// Payment amount mismatch
    #[error("payment amount mismatch: expected {expected}, got {actual}")]
    AmountMismatch {
        /// The expected amount in atomic units
        expected: u64,
        /// The actual amount seen on-chain in atomic units
        actual: u64,
    },
    /// Payment has not reached the required confirmations
    #[error("insufficient confirmations: {0}")]
    InsufficientConfirmations(u32),
    /// Payment timed out
    #[error("payment timeout")]
    Timeout,
    /// Currency has no working watcher implementation
    #[error("unsupported currency: {0}")]
    UnsupportedCurrency(String),
}

/// Trait for watching a blockchain for incoming payments
#[async_trait]
pub trait BlockchainWatcher: Send + Sync {
    /// Generate a new receive address for a payment
    async fn generate_address(&self) -> Result<String, PaymentError>;

    /// Check if a payment has been received at the given address
    ///
    /// Returns `Some(confirmations)` if received, `None` if not yet seen.
    async fn check_payment(
        &self,
        address: &str,
        expected_amount: u64,
        tx_hash: Option<&str>,
    ) -> Result<Option<u32>, PaymentError>;

    /// Get the currency this watcher supports
    fn currency(&self) -> Currency;
}

/// Monero blockchain watcher using `monero-wallet-rpc` JSON-RPC
pub struct MoneroWatcher {
    rpc_url: String,
    client: reqwest::Client,
}

impl MoneroWatcher {
    /// Create a watcher for the given `monero-wallet-rpc` URL
    pub fn new(rpc_url: String) -> Self {
        Self {
            rpc_url,
            client: reqwest::Client::new(),
        }
    }

    async fn rpc_call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, PaymentError> {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "0",
            "method": method,
            "params": params
        });

        let response = self
            .client
            .post(&self.rpc_url)
            .json(&request)
            .send()
            .await
            .map_err(|e| PaymentError::RpcError(e.to_string()))?
            .json::<serde_json::Value>()
            .await
            .map_err(|e| PaymentError::RpcError(e.to_string()))?;

        if let Some(err) = response.get("error") {
            return Err(PaymentError::RpcError(format!("RPC error: {}", err)));
        }

        Ok(response)
    }
}

#[async_trait]
impl BlockchainWatcher for MoneroWatcher {
    async fn generate_address(&self) -> Result<String, PaymentError> {
        let response = self
            .rpc_call("create_address", serde_json::json!({"account_index": 0}))
            .await?;
        let address = response["result"]["address"]
            .as_str()
            .ok_or_else(|| PaymentError::AddressGenerationFailed("No address in response".into()))?;
        Ok(address.to_string())
    }

    async fn check_payment(
        &self,
        address: &str,
        expected_amount: u64,
        _tx_hash: Option<&str>,
    ) -> Result<Option<u32>, PaymentError> {
        // get_transfers lists incoming transfers to the wallet's addresses.
        // The RPC has no address filter parameter, so transfers are
        // filtered code-side; each request uses a fresh subaddress, which
        // keeps the match unambiguous.
        let response = self
            .rpc_call(
                "get_transfers",
                serde_json::json!({
                    "in": true,
                    "filter_by_height": false,
                    "address": address
                }),
            )
            .await?;

        let transfers = response["result"]["in"]
            .as_array()
            .ok_or_else(|| PaymentError::RpcError("No transfers in response".into()))?;

        for transfer in transfers {
            if transfer["address"].as_str() != Some(address) {
                continue;
            }
            let amount = transfer["amount"].as_u64().unwrap_or(0);
            if amount >= expected_amount {
                let confirmations = transfer["confirmations"].as_u64().unwrap_or(0) as u32;
                return Ok(Some(confirmations));
            }
        }

        Ok(None)
    }

    fn currency(&self) -> Currency {
        Currency::Monero
    }
}

/// Darkfi blockchain watcher (stub)
///
/// TODO: Implement Darkfi blockchain watcher once darkfid's wallet RPC API
/// stabilizes. Follow the [`MoneroWatcher`] pattern: implement
/// [`BlockchainWatcher`] against the daemon's JSON-RPC.
pub struct DarkfiWatcher {
    /// Darkfi daemon RPC URL
    pub rpc_url: String,
}

impl DarkfiWatcher {
    /// Create a watcher for the given darkfid RPC URL
    pub fn new(rpc_url: String) -> Self {
        Self { rpc_url }
    }
}

#[async_trait]
impl BlockchainWatcher for DarkfiWatcher {
    async fn generate_address(&self) -> Result<String, PaymentError> {
        // TODO: Implement Darkfi blockchain watcher
        Err(PaymentError::UnsupportedCurrency(Currency::Darkfi.as_str().to_string()))
    }

    async fn check_payment(
        &self,
        _address: &str,
        _expected_amount: u64,
        _tx_hash: Option<&str>,
    ) -> Result<Option<u32>, PaymentError> {
        // TODO: Implement Darkfi blockchain watcher
        Err(PaymentError::UnsupportedCurrency(Currency::Darkfi.as_str().to_string()))
    }

    fn currency(&self) -> Currency {
        Currency::Darkfi
    }
}

/// Navio blockchain watcher (stub)
///
/// TODO: Implement Navio blockchain watcher (bitcoin-core-style RPC:
/// `getnewaddress` / `listreceivedbyaddress`) following the
/// [`MoneroWatcher`] pattern.
pub struct NavioWatcher {
    /// Navio daemon RPC URL
    pub rpc_url: String,
}

impl NavioWatcher {
    /// Create a watcher for the given navcoind RPC URL
    pub fn new(rpc_url: String) -> Self {
        Self { rpc_url }
    }
}

#[async_trait]
impl BlockchainWatcher for NavioWatcher {
    async fn generate_address(&self) -> Result<String, PaymentError> {
        // TODO: Implement Navio blockchain watcher
        Err(PaymentError::UnsupportedCurrency(Currency::Navio.as_str().to_string()))
    }

    async fn check_payment(
        &self,
        _address: &str,
        _expected_amount: u64,
        _tx_hash: Option<&str>,
    ) -> Result<Option<u32>, PaymentError> {
        // TODO: Implement Navio blockchain watcher
        Err(PaymentError::UnsupportedCurrency(Currency::Navio.as_str().to_string()))
    }

    fn currency(&self) -> Currency {
        Currency::Navio
    }
}

/// Build the watcher for a currency from the blockchain configuration
///
/// Darkfi and Navio currently return stub watchers whose calls fail with
/// [`PaymentError::UnsupportedCurrency`] until their RPC implementations
/// are filled in.
pub fn create_watcher(
    currency: Currency,
    config: &BlockchainConfig,
) -> std::sync::Arc<dyn BlockchainWatcher> {
    match currency {
        Currency::Monero => std::sync::Arc::new(MoneroWatcher::new(config.monero_rpc_url.clone())),
        Currency::Darkfi => std::sync::Arc::new(DarkfiWatcher::new(config.darkfi_rpc_url.clone())),
        Currency::Navio => std::sync::Arc::new(NavioWatcher::new(config.navio_rpc_url.clone())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_currency_from_str() {
        assert_eq!(Currency::from_str("xmr"), Some(Currency::Monero));
        assert_eq!(Currency::from_str("Monero"), Some(Currency::Monero));
        assert_eq!(Currency::from_str("dark"), Some(Currency::Darkfi));
        assert_eq!(Currency::from_str("DARKFI"), Some(Currency::Darkfi));
        assert_eq!(Currency::from_str("nav"), Some(Currency::Navio));
        assert_eq!(Currency::from_str("navio"), Some(Currency::Navio));
        assert_eq!(Currency::from_str("btc"), None);
        assert_eq!(Currency::from_str(""), None);
    }

    #[test]
    fn test_currency_to_byte_from_byte() {
        for currency in [Currency::Monero, Currency::Darkfi, Currency::Navio] {
            assert_eq!(Currency::from_byte(currency.to_byte()), Some(currency));
        }
        assert_eq!(Currency::from_byte(3), None);
        assert_eq!(Currency::from_byte(255), None);
        assert_eq!(Currency::Monero.as_str(), "XMR");
        assert_eq!(Currency::Darkfi.as_str(), "DARK");
        assert_eq!(Currency::Navio.as_str(), "NAV");
    }

    #[test]
    fn test_compute_pricing_default() {
        let pricing = ComputePricing::default();
        // Default pricing is zero = free compute
        assert_eq!(pricing.price_per_execution, 0);
        assert_eq!(pricing.price_per_cpu_sec, 0);
        assert_eq!(pricing.price_per_mb, 0);
        assert!(pricing.is_free());
        assert_eq!(pricing.accepted_currencies, vec![Currency::Monero]);
        assert_eq!(pricing.required_confirmations, 1);

        // Paid pricing: worst-case quote uses the execution caps
        let paid = ComputePricing {
            price_per_execution: 100,
            price_per_cpu_sec: 50,
            price_per_mb: 10,
            ..Default::default()
        };
        assert!(!paid.is_free());
        assert!(paid.accepts(Currency::Monero));
        assert!(!paid.accepts(Currency::Navio));
        // 2500ms -> 3 cpu secs; 64 MB
        assert_eq!(paid.amount_due(2500, 64), 100 + 50 * 3 + 10 * 64);
    }

    #[test]
    fn test_payment_request_serialization() {
        let quote = PaymentRequest {
            request_id: [0xA1u8; 32],
            currency: Currency::Monero,
            amount: 1_000_000_000,
            address: "4A1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx".to_string(),
            required_confirmations: 10,
        };

        let serialized =
            static_storage::compute::serialize_payment_request(&quote).unwrap();
        let back = static_storage::compute::deserialize_payment_request(&serialized).unwrap();
        assert_eq!(back, quote);
    }

    #[test]
    fn test_payment_confirmation_serialization() {
        let confirmation = PaymentConfirmation {
            request_id: [0xB2u8; 32],
            tx_hash: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
                .to_string(),
            currency: Currency::Monero,
        };

        let serialized =
            static_storage::compute::serialize_payment_confirmation(&confirmation).unwrap();
        let back =
            static_storage::compute::deserialize_payment_confirmation(&serialized).unwrap();
        assert_eq!(back, confirmation);
    }

    #[test]
    fn test_payment_state_transitions() {
        let quote = PaymentRequest {
            request_id: [0xC3u8; 32],
            currency: Currency::Monero,
            amount: 500,
            address: "addr".to_string(),
            required_confirmations: 1,
        };

        // 1. Awaiting payment after the quote is sent
        let mut state = PaymentState::AwaitingPayment {
            request: quote.clone(),
            sent_at: 1000,
        };
        assert!(matches!(state, PaymentState::AwaitingPayment { ref request, .. } if request.request_id == quote.request_id));

        // 2. Payment confirmed on-chain
        state = PaymentState::PaymentConfirmed {
            tx_hash: "abc".to_string(),
            confirmed_at: 2000,
        };
        assert!(matches!(state, PaymentState::PaymentConfirmed { ref tx_hash, .. } if tx_hash == "abc"));

        // 3. Timeout when the requester never pays
        state = PaymentState::PaymentTimeout;
        assert!(matches!(state, PaymentState::PaymentTimeout));
    }
}
