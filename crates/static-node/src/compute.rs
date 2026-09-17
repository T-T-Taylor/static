//! WASM compute execution for Static compute providers
//!
//! Executes sandboxed WASM modules for compute requests received through
//! the Sphinx mixnet. Modules export a `process(input_ptr, input_len) ->
//! output_ptr` function over an exported `memory`; input bytes are written
//! at the end of the module's memory, and the module returns a pointer to
//! a `[4-byte length][data]` output region.
//!
//! Sandboxing guarantees for the MVP:
//! - No WASI: modules have no filesystem, network, clock, or environment
//!   access. Only linear memory and pure computation are available.
//! - CPU limiting via Wasmtime fuel (approx. 1 fuel per instruction).
//! - Memory limiting via a [`ComputeLimiter`] resource limiter that also
//!   tracks peak usage.
//! - Execution runs on a blocking thread so the async runtime is not
//!   starved.
//!
//! Confidentiality: none for the MVP (the provider sees inputs and
//! outputs). The request/response types carry resource and fee metadata so
//! a future TEE-based provider can attest execution without protocol
//! changes.

use static_mesh::fragment::{fragment_payload, serialize_fragment};
use static_sphinx::SphinxPacket;
use static_storage::compute::{ComputeRequest, ComputeResponse, ReturnRoute, MAX_COMPUTE_OUTPUT_SIZE};
use thiserror::Error;
use wasmtime::{Config, Engine, Instance, Module, ResourceLimiter, Store, Val};

/// Errors that can occur during compute handling
#[derive(Debug, Error)]
pub enum ComputeError {
    /// WASM module failed to compile
    #[error("module compilation failed: {0}")]
    ModuleCompilationFailed(String),
    /// WASM module failed to instantiate
    #[error("instantiation failed: {0}")]
    InstantiationFailed(String),
    /// Module does not export a `process` function
    #[error("process function not found")]
    ProcessFunctionNotFound,
    /// Module does not export a `memory`
    #[error("memory not found")]
    MemoryNotFound,
    /// Could not grow module memory to fit the input
    #[error("memory allocation failed")]
    MemoryAllocationFailed,
    /// Writing the input into module memory failed
    #[error("memory write failed: {0}")]
    MemoryWriteFailed(String),
    /// Reading the output from module memory failed
    #[error("memory read failed: {0}")]
    MemoryReadFailed(String),
    /// Module output exceeds the response size cap
    #[error("module output too large")]
    OutputTooLarge,
    /// Execution trapped (including fuel exhaustion)
    #[error("execution failed: {0}")]
    ExecutionFailed(String),
    /// Setting the fuel limit failed
    #[error("fuel error: {0}")]
    FuelError(String),
    /// Module content is not available locally or on the network
    #[error("module not found on network")]
    ModuleNotFound,
    /// Offered fee is below the minimum accepted
    #[error("fee insufficient")]
    FeeInsufficient,
    /// Node is already executing the maximum number of requests
    #[error("capacity exceeded")]
    CapacityExceeded,
    /// Sphinx packet creation failed
    #[error("sphinx packet creation failed")]
    SphinxError,
    /// Serialization failed
    #[error("serialization failed: {0}")]
    Serialization(String),
}

/// Memory/cost accounting and limits for one WASM execution
struct ComputeLimiter {
    /// Maximum linear memory the module may grow to (bytes)
    max_memory_bytes: usize,
    /// Peak memory requested so far (bytes)
    peak_memory: usize,
}

impl ResourceLimiter for ComputeLimiter {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> Result<bool, wasmtime::Error> {
        self.peak_memory = self.peak_memory.max(desired);
        Ok(desired <= self.max_memory_bytes)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> Result<bool, wasmtime::Error> {
        Ok(desired <= 10_000)
    }
}

/// Execute a WASM module with the given input
///
/// Returns `(output_data, cpu_time_ms, memory_used_bytes)`. CPU time is a
/// wall-clock measurement of the call; fuel exhaustion raises
/// [`ComputeError::ExecutionFailed`].
pub fn execute_wasm(
    module_bytes: &[u8],
    input_data: &[u8],
    max_cpu_ms: u64,
    max_memory_mb: u32,
) -> Result<(Vec<u8>, u64, u64), ComputeError> {
    // Fuel budget: ~1 fuel per WASM instruction, budgeted generously at
    // 1M fuel per permitted millisecond. Fuel is a hard cap on executed
    // instructions; wall-clock time additionally bounds host-side work.
    let fuel_budget = max_cpu_ms.saturating_mul(1_000_000);

    let mut config = Config::new();
    config.consume_fuel(true);
    let engine = Engine::new(&config)
        .map_err(|e| ComputeError::ModuleCompilationFailed(e.to_string()))?;

    let module = Module::new(&engine, module_bytes)
        .map_err(|e| ComputeError::ModuleCompilationFailed(e.to_string()))?;

    let limiter = ComputeLimiter {
        max_memory_bytes: max_memory_mb as usize * 1024 * 1024,
        peak_memory: 0,
    };
    let mut store = Store::new(&engine, limiter);
    store
        .set_fuel(fuel_budget)
        .map_err(|e| ComputeError::FuelError(e.to_string()))?;
    store.limiter(|data| data);

    let instance = Instance::new(&mut store, &module, &[])
        .map_err(|e| ComputeError::InstantiationFailed(e.to_string()))?;

    let process = instance
        .get_func(&mut store, "process")
        .ok_or(ComputeError::ProcessFunctionNotFound)?;

    let memory = instance
        .get_memory(&mut store, "memory")
        .ok_or(ComputeError::MemoryNotFound)?;

    // Write the input at the end of the current memory, growing by whole
    // pages (64 KiB each) as needed.
    let input_ptr = memory.data_size(&store);
    let pages_needed = input_data.len().div_ceil(64 * 1024) as u64;
    if pages_needed > 0 {
        memory
            .grow(&mut store, pages_needed)
            .map_err(|_| ComputeError::MemoryAllocationFailed)?;
    }
    memory
        .write(&mut store, input_ptr, input_data)
        .map_err(|e| ComputeError::MemoryWriteFailed(e.to_string()))?;

    // Call process(input_ptr, input_len) -> output_ptr
    let mut results = [Val::I32(0)];
    let call_started = std::time::Instant::now();
    let call_result = process.call(
        &mut store,
        &[
            Val::I32(input_ptr as i32),
            Val::I32(input_data.len() as i32),
        ],
        &mut results,
    );
    let cpu_time_ms = call_started.elapsed().as_millis() as u64;

    if let Err(e) = call_result {
        // Fuel exhaustion surfaces as a trap; classify it so callers can
        // distinguish resource exhaustion from module bugs.
        if e.downcast_ref::<wasmtime::Trap>() == Some(&wasmtime::Trap::OutOfFuel) {
            return Err(ComputeError::ExecutionFailed("out of fuel".to_string()));
        }
        return Err(ComputeError::ExecutionFailed(e.to_string()));
    }

    let output_ptr = results[0]
        .i32()
        .map(|v| v as u32 as usize)
        .ok_or_else(|| ComputeError::ExecutionFailed("process returned no pointer".to_string()))?;

    // Read the output: [4-byte LE length][data]
    let memory_size = memory.data_size(&store);
    if output_ptr.checked_add(4).map(|end| end <= memory_size) != Some(true) {
        return Err(ComputeError::MemoryReadFailed(
            "output length out of bounds".to_string(),
        ));
    }
    let mut len_bytes = [0u8; 4];
    memory
        .read(&store, output_ptr, &mut len_bytes)
        .map_err(|e| ComputeError::MemoryReadFailed(e.to_string()))?;
    let output_len = u32::from_le_bytes(len_bytes) as usize;

    if output_len > MAX_COMPUTE_OUTPUT_SIZE {
        return Err(ComputeError::OutputTooLarge);
    }
    if output_ptr + 4 + output_len > memory_size {
        return Err(ComputeError::MemoryReadFailed(
            "output data out of bounds".to_string(),
        ));
    }

    let mut output_data = vec![0u8; output_len];
    memory
        .read(&store, output_ptr + 4, &mut output_data)
        .map_err(|e| ComputeError::MemoryReadFailed(e.to_string()))?;

    let peak_memory = store.into_data().peak_memory;

    Ok((output_data, cpu_time_ms.max(1), peak_memory as u64))
}

/// Build the Sphinx packets carrying a compute request to a provider
///
/// The serialized request is fragmented into Sphinx-body-sized pieces; each
/// fragment becomes one packet routed through `forward_route`.
pub fn build_request_packets(
    request: &ComputeRequest,
    forward_route: &static_sphinx::Route,
) -> Result<Vec<SphinxPacket>, ComputeError> {
    let payload = static_storage::compute::serialize_request(request)
        .map_err(|e| ComputeError::Serialization(e.to_string()))?;

    let mut packets = Vec::new();
    for fragment in fragment_payload(&payload) {
        let body = serialize_fragment(&fragment);
        let packet = static_sphinx::create_packet(forward_route, &body)
            .map_err(|_| ComputeError::SphinxError)?;
        packets.push(packet);
    }
    Ok(packets)
}

/// Build the Sphinx packets carrying a compute response back to a requester
///
/// The serialized response is fragmented; each fragment becomes one packet
/// routed through the request's return route (reply-block style).
pub fn build_response_packets(
    response: &ComputeResponse,
    return_route: &ReturnRoute,
) -> Result<Vec<SphinxPacket>, ComputeError> {
    let payload = static_storage::compute::serialize_response(response)
        .map_err(|e| ComputeError::Serialization(e.to_string()))?;

    let mut packets = Vec::new();
    for fragment in fragment_payload(&payload) {
        let body = serialize_fragment(&fragment);
        let packet = static_sphinx::create_packet(&return_route.to_sphinx_route(), &body)
            .map_err(|_| ComputeError::SphinxError)?;
        packets.push(packet);
    }
    Ok(packets)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Echo module: copies the input to a scratch area at address 1024 and
    /// returns a pointer to `[4-byte length][data]` there.
    const ECHO_WAT: &str = r#"
        (module
          (memory (export "memory") 1)
          (func (export "process") (param $ptr i32) (param $len i32) (result i32)
            (local $out i32)
            (local.set $out (i32.const 1024))
            (i32.store (local.get $out) (local.get $len))
            (memory.copy (i32.add (local.get $out) (i32.const 4)) (local.get $ptr) (local.get $len))
            (local.get $out)))
    "#;

    /// Infinite loop: must be killed by the fuel limit.
    const INFINITE_LOOP_WAT: &str = r#"
        (module
          (memory (export "memory") 1)
          (func (export "process") (param i32 i32) (result i32)
            (loop (br 0))
            (unreachable)))
    "#;

    /// Attempts to grow memory to 256 MiB regardless of the limiter.
    const MEMORY_HOG_WAT: &str = r#"
        (module
          (memory (export "memory") 1)
          (func (export "process") (param i32 i32) (result i32)
            (if (i32.eq (memory.grow (i32.const 4096)) (i32.const -1))
              (then (unreachable)))
            (i32.const 0)))
    "#;

    #[test]
    fn test_wasm_execution_simple() {
        let input = b"hello compute world".to_vec();
        let (output, _cpu_ms, _mem) = execute_wasm(ECHO_WAT.as_bytes(), &input, 5000, 64)
            .expect("echo execution should succeed");

        assert_eq!(output, input);
    }

    #[test]
    fn test_wasm_execution_resource_limits_cpu() {
        let result = execute_wasm(INFINITE_LOOP_WAT.as_bytes(), &[], 100, 64);

        match result {
            Err(ComputeError::ExecutionFailed(msg)) => {
                assert!(
                    msg.contains("fuel") || msg.contains("fuel") || msg.contains("trap"),
                    "expected fuel exhaustion, got: {}",
                    msg
                );
            }
            other => panic!("expected fuel-exhaustion error, got: {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn test_wasm_execution_resource_limits_memory() {
        let result = execute_wasm(MEMORY_HOG_WAT.as_bytes(), &[], 5000, 64);

        // The limiter denies the grow (or the module traps on -1); either
        // way the execution must fail, not allocate 256 MiB.
        assert!(
            matches!(
                result,
                Err(ComputeError::ExecutionFailed(_)) | Err(ComputeError::MemoryAllocationFailed)
            ),
            "expected memory-limit failure, got: {:?}",
            result.map(|_| ())
        );
    }
}
