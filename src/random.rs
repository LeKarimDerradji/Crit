//! Randomness helpers used across the Crit crate.
//!
//! For now only the OS-backed RNG is exposed to support cryptographic key
//! generation. Once the state synchronization layer is implemented, revisit
//! this module to adopt a consensus-aware source of randomness if needed.

use rand_core::OsRng;

/// Returns an operating system backed RNG suitable for cryptographic usage.
pub(crate) fn crypto_rng() -> OsRng {
    OsRng
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::RngCore;

    #[test]
    fn crypto_rng_produces_values() {
        let mut rng = crypto_rng();
        let first = rng.next_u64();
        let second = rng.next_u64();
        assert_ne!(
            first, second,
            "OsRng should provide non-repeating draws with high probability"
        );
    }
}
