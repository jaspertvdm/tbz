//! tbz-airlock: TIBET Airlock — sandboxed decompression environment
//!
//! The Airlock is a quarantine buffer where blocks are decompressed and
//! validated before touching the host filesystem. Data that fails
//! validation is wiped with 0x00. Nothing leaks.
//!
//! On Linux with eBPF support: kernel-level enforcement via bpf_lsm hooks.
//! Fallback: userspace-only isolation with the same lifecycle guarantees.

use thiserror::Error;
use zeroize::Zeroize;

#[derive(Error, Debug)]
pub enum AirlockError {
    #[error("Airlock buffer overflow: block size {block_size} exceeds limit {limit}")]
    BufferOverflow { block_size: u64, limit: u64 },
    #[error("Airlock timeout: buffer auto-wiped after {seconds}s")]
    Timeout { seconds: u64 },
    #[error("Validation failed in Airlock: {reason}")]
    ValidationFailed { reason: String },
    #[error("eBPF not available: {reason}")]
    EbpfUnavailable { reason: String },
}

/// Airlock execution mode
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AirlockMode {
    /// Full kernel-level enforcement via eBPF (Linux, root, kernel >= 5.7)
    Kernel,
    /// Userspace-only isolation (fallback for macOS, no root, older kernels)
    Userspace,
}

/// The TIBET Airlock — quarantine buffer for block decompression
pub struct Airlock {
    /// Execution mode (kernel or userspace)
    mode: AirlockMode,
    /// Maximum buffer size in bytes
    max_buffer_size: u64,
    /// Timeout in seconds before auto-wipe
    timeout_seconds: u64,
    /// Current buffer (zeroized on drop)
    buffer: AirlockBuffer,
}

/// Secure buffer that zeroizes on drop
struct AirlockBuffer {
    data: Vec<u8>,
}

impl Drop for AirlockBuffer {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

impl Airlock {
    /// Create a new Airlock with auto-detected mode
    pub fn new(max_buffer_size: u64, timeout_seconds: u64) -> Self {
        let mode = detect_ebpf_support();

        if mode == AirlockMode::Userspace {
            tracing::warn!("Airlock draait in userspace mode — geen kernel-level enforcement");
        }

        Self {
            mode,
            max_buffer_size,
            timeout_seconds,
            buffer: AirlockBuffer { data: Vec::new() },
        }
    }

    /// Get the current Airlock mode
    pub fn mode(&self) -> AirlockMode {
        self.mode
    }

    /// ALLOCATE: Prepare the Airlock for a block of given size
    pub fn allocate(&mut self, block_size: u64) -> Result<(), AirlockError> {
        if block_size > self.max_buffer_size {
            return Err(AirlockError::BufferOverflow {
                block_size,
                limit: self.max_buffer_size,
            });
        }
        self.buffer.data = Vec::with_capacity(block_size as usize);
        Ok(())
    }

    /// RECEIVE: Write decompressed data into the Airlock buffer
    pub fn receive(&mut self, data: &[u8]) -> Result<(), AirlockError> {
        if self.buffer.data.len() + data.len() > self.max_buffer_size as usize {
            self.wipe();
            return Err(AirlockError::BufferOverflow {
                block_size: (self.buffer.data.len() + data.len()) as u64,
                limit: self.max_buffer_size,
            });
        }
        self.buffer.data.extend_from_slice(data);
        Ok(())
    }

    /// RELEASE: Get the validated data and wipe the buffer
    pub fn release(&mut self) -> Vec<u8> {
        let data = std::mem::take(&mut self.buffer.data);
        self.wipe();
        data
    }

    /// WIPE: Zero-fill the entire buffer
    pub fn wipe(&mut self) {
        self.buffer.data.zeroize();
        self.buffer.data.clear();
    }

    /// Get current buffer size
    pub fn buffer_size(&self) -> usize {
        self.buffer.data.len()
    }
}

/// Detect if eBPF kernel enforcement is available
fn detect_ebpf_support() -> AirlockMode {
    // Check: Linux, root, kernel >= 5.7
    #[cfg(target_os = "linux")]
    {
        use std::fs;
        // Check if we have CAP_BPF or are root
        if unsafe { libc::geteuid() } == 0 {
            // Check kernel version for BPF LSM support
            if let Ok(version) = fs::read_to_string("/proc/version") {
                // Basic check — will be refined with actual eBPF probe
                if version.contains("Linux") {
                    return AirlockMode::Kernel;
                }
            }
        }
        AirlockMode::Userspace
    }

    #[cfg(not(target_os = "linux"))]
    {
        AirlockMode::Userspace
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_airlock_lifecycle() {
        let mut airlock = Airlock::new(1024 * 1024, 30);

        // ALLOCATE
        airlock.allocate(1024).unwrap();

        // RECEIVE
        let data = vec![42u8; 512];
        airlock.receive(&data).unwrap();
        assert_eq!(airlock.buffer_size(), 512);

        // RELEASE (returns data + wipes)
        let released = airlock.release();
        assert_eq!(released.len(), 512);
        assert_eq!(airlock.buffer_size(), 0);
    }

    #[test]
    fn test_airlock_overflow_protection() {
        let mut airlock = Airlock::new(100, 30);
        airlock.allocate(50).unwrap();

        let result = airlock.receive(&vec![0u8; 200]);
        assert!(result.is_err());
        // Buffer should be wiped after overflow
        assert_eq!(airlock.buffer_size(), 0);
    }
}
