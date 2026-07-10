# Runt — Hackathon Demo Guide

## 2-Minute Video Storyboard

### 0:00-0:20 — The Problem
"Verifying Ethereum proofs is fragmented. State proofs use one library, ZK proofs another, consensus proofs another. Every chain, every bridge, every light client reinvents the same wheel. What if there was one runtime that could verify ANY Ethereum proof, anywhere?"

### 0:20-0:45 — The Architecture
Show terminal:
```
$ runt list
WASM modules loaded: 5
Verifiers registered: 5

  state:eip1186     v0.1.0 (mpt)       EIP-1186 Merkle Patricia Trie state proof verifier
  tx:receipt        v0.1.0 (mpt)       Transaction receipt inclusion proof verifier
  consensus:altair  v0.1.0 (sync-comm) Altair sync committee light client proof verifier
  groth16:bn254     v0.1.0 (groth16)   BN254 Groth16 zero-knowledge proof verifier
  hello:dummy       v0.1.0 (dummy)     Hello-world verifier for testing
```

"Five verifiers, each a tiny WASM module. 748 bytes to 32KB. Portable anywhere WASM runs — browsers, servers, edge, even inside other blockchains."

### 0:45-1:15 — Demo: State Proof Verification
"Let me verify a real Ethereum account proof. Here's an EIP-1186 proof: Merkle Patricia Trie nodes proving an account exists at this state root. 246 microseconds. Valid."

Show:
```
$ runt verify --proof-type state:eip1186 --proof-file proof.bin
status: VALID
time: 246.79µs
```

"Under the hood: the WASM module decoded RLP, walked the trie, verified every hash using the host's native keccak256 engine. All inside a sandboxed, deterministic environment."

### 1:15-1:45 — Why It Matters
"Here's why this is powerful:

- **Cross-chain bridges**: Verify Ethereum state on any chain that can run WASM
- **Light clients**: Verify consensus proofs in a browser — trustless access to Ethereum
- **ZK rollups**: Verify Groth16 proofs using native BN254 pairings — no precompile needed
- **Modular blockchains**: Plug in ANY proof system as a .wasm file

Every verifier implements the same interface. New proof types? Drop in a .wasm file. It auto-registers."

### 1:45-2:00 — Call to Action
"Runt is MIT licensed. 18 integration tests. Real BLS and BN254 crypto. The WASM modules are 748 bytes to 32KB. Build your verifier, drop it in, verify anything, anywhere."

## Live Demo Commands

```bash
# Build everything
make verifiers

# List all loaded verifiers
cargo run -p runt-cli -- list

# Verify an EIP-1186 state proof
cargo run -p runt-cli -- verify \
  --proof-type state:eip1186 \
  --proof-file test-vectors/account_proof.bin

# Verify a transaction receipt proof
cargo run -p runt-cli -- verify \
  --proof-type tx:receipt \
  --proof-file test-vectors/receipt_proof.bin

# Verify a consensus proof (sync committee)
cargo run -p runt-cli -- verify \
  --proof-type consensus:altair \
  --proof-file test-vectors/light_client_update.bin

# Verify a Groth16 proof
cargo run -p runt-cli -- verify \
  --proof-type groth16:bn254 \
  --proof-file test-vectors/zk_proof.bin

# Run all tests (18 passing)
make test
```

## Hackathon Use Cases

### 1. Cross-Chain Bridge Verifier
Build a bridge that verifies Ethereum state on any destination chain:
- Lock tokens on Ethereum → generate EIP-1186 proof of locked state
- WASM verifier runs on destination chain → verifies the proof
- Unlock tokens on destination

### 2. Browser-Based Light Client
Embed Runt in a web app via wasm-bindgen:
- Fetch Altair light client updates from beacon API
- Verify sync committee signatures in the browser
- Trustless Ethereum access without running a full node

### 3. ZK Rollup Validator
Use Runt as the verification layer for a ZK rollup:
- Generate Groth16 proofs off-chain
- Verify on-chain or off-chain using the BN254 pairing host
- Switch proof systems by swapping .wasm modules

### 4. Multi-Provenance Oracle
Verify data from multiple sources using different proof types:
- State proof → prove an account balance
- Receipt proof → prove a transaction happened
- Consensus proof → prove it's in the canonical chain

### 5. Modular Blockchain Framework
Build a blockchain where verification is a configurable module:
- Each verifier is a .wasm module loaded at runtime
- Upgrade verification logic without hard forks
- Support new proof systems by dropping in new modules

## Adding a Custom Verifier (30 seconds)

```rust
// runt-verifiers/my-verifier/src/lib.rs
#[link(wasm_import_module = "env")]
extern "C" {
    fn host_hash(algorithm: u32, input: *const u8, input_len: u32, output: *mut u8);
}

#[no_mangle]
pub extern "C" fn metadata(buf: *mut u8, buf_len: u32) -> u32 {
    let json = r#"{"proof_type_id":"my:custom","version":"0.1.0",...}"#;
    // copy to buf, return length
}

#[no_mangle]
pub extern "C" fn verify(proof: *const u8, proof_len: u32,
    inputs: *const u8, inputs_len: u32,
    error_buf: *mut u8, error_buf_len: u32) -> u32 {
    // your verification logic here
    // return 0=valid, 1=invalid, 2=error
}
```

```bash
cargo build --target wasm32-unknown-unknown --release -p my-verifier
cp target/wasm32-unknown-unknown/release/my_verifier.wasm target/verifiers/
cargo run -p runt-cli -- list  # your verifier appears!
```

## One-Liners

```bash
# Build all 5 verifiers
make verifiers

# List them
cargo run -p runt-cli -- list

# Verify anything
cargo run -p runt-cli -- verify --proof-type state:eip1186 --proof-file proof.bin

# 18 tests, zero failures
make test
```
