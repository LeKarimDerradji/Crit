## Research
- Research whether representing Crit amounts with 256 bits is appropriate, considering Ethereum compatibility and cross-chain interoperability implications.
- Explore better pub/address format for accounts and document how it maps to `AccountId` (see `src/account.rs`).
- Research for best crypto primitives on pub/key gen and source of randomness

## Todos
- Check visibility of inner modules components
- check usefullness of derive attributes associated to struct and enum (Default, Hash etc);
- add chain id to avoid replay on other chains (if exists) on wallet or account module.


## Signed ACK + Mempool Commitment: Anti-Withholding / Anti-Censorship
Problem. In networks where the proposer freely picks a transaction list, a node can withhold lucrative transactions or censor privately received ones—without any provable evidence. This leads to arbitrary inclusion, execution delays, and trust erosion.

Solution (brief).
A three-part, verifiable, and enforceable scheme:
  1.	Signed ACK (receipt of reception).
On directed submit, the validator returns
Ack = SigV(H(tx) || ckpt_seen || expires_at || qos) → cryptographic proof it received an eligible tx no later than the referenced checkpoint.
  2.	Periodic mempool commitment.
At each checkpoint, every validator publishes
MempoolCommit{ckpt, root} where root is a Merkle/KZG root over the eligible, seen tx_hash set. → Enables presence/absence proofs after the fact.
  3.	Inclusion SLA + penalties.
If a validator ACKed a tx, it must (a) include it as soon as feasible, or (b) prove its continuous presence in its MempoolCommits, or (c) issue a signed NACK with a concrete reason (conflict, insufficient fee, etc.). Otherwise: penalty (reputation/slashing-light, fee redistribution).


Benefits. Provable withholding, incentivized relay & inclusion, measurable censorship, and compatibility with PBS/relays and inclusion lists.