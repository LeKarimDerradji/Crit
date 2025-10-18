//! Network identifiers used to scope Crit transactions and state.
//!
//! Transactions include the network identifier in their signed payload so that
//! the same operation cannot be replayed across distinct chains. These
//! constants provide well-known IDs for the production and test environments
//! while keeping the actual type as a simple `u8` for serialization efficiency.

/// Alias describing the identifier of a Crit network.
pub type NetId = u8;

/// Identifier assigned to the canonical Crit main network.
pub const MAIN_NET: NetId = 1;

/// Identifier assigned to the public test network.
pub const TEST_NET: NetId = 2;
