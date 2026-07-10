# Runt

**Runt** is a portable, composable, deterministic, and extensible WASM verification runtime for Ethereum proofs.

## Principles

- **Portable**: Runs anywhere WASM runs — browser, server, edge, mobile.
- **Composable**: Every verifier implements a common WIT interface. Verifiers can delegate to one another.
- **Deterministic**: No networking, no hidden state, no non-deterministic floating-point in the core. Identical outputs on every architecture.
- **Extensible**: New proof types are added by dropping a `.wasm` component file into the verifiers directory.

## Architecture

```
┌──────────────────────────────────────────────────┐
│                   runt-cli                        │
│         (CLI, WASI host, integration)             │
├──────────────────────────────────────────────────┤
│                  runt-host                        │
│   VerifierRegistry, VerifierLoader, Capability    │
│   Index, Dependency Graph, Host Crypto Providers  │
├──────────────────────────────────────────────────┤
│                  runt-wit                         │
│   WIT definitions + wit-bindgen generated code    │
│   Interfaces: verifier, host-crypto, host-storage │
├──────────────────────────────────────────────────┤
│                 runt-core                         │
│   wasmtime engine, fuel metering, sandbox config  │
│   Store management, epoch interruption            │
├──────────────────────────────────────────────────┤
│              runt-verifiers/                      │
│   Reference WASM components implementing Verifier │
│   ├── state-verifier   (EIP-1186 MPT)            │
│   ├── tx-verifier      (Receipt proofs)           │
│   ├── consensus-verifier (Altair sync committee)  │
│   └── groth16-verifier (BN254 Groth16)            │
└──────────────────────────────────────────────────┘
```

## Verifier Interface (WIT)

Every verifier is a WASM component that exports:

```wit
interface verifier {
    variant verification-status { valid, invalid(string), error(string) }

    record verifier-metadata {
        proof-type-id: string,
        version: string,
        curve: string,
        scheme: string,
        %supports-recursion: bool,
        %trusted-setup-required: bool,
        %max-proof-size: u64,
        description: string,
    }

    metadata: func() -> verifier-metadata;
    verify: func(
        proof: borrow<list<u8>>,
        public-inputs: borrow<list<u8>>,
        verification-key: borrow<list<u8>>
    ) -> verification-status;
}
```

Verifiers import cryptographic primitives from the host (`host-crypto`) and verification keys from `host-storage`. The sandbox never touches raw key material directly.

## Quick Start

```bash
cargo build --workspace
cargo run -- list                          # list loaded verifiers
cargo run -- verify state proof.json       # verify an EIP-1186 state proof
```

## Verifier Types

| Verifier | Proof Type | Status |
|---|---|---|
| `state-verifier` | EIP-1186 Merkle Patricia Trie proofs | Planned |
| `tx-verifier` | Transaction inclusion & receipt proofs | Planned |
| `consensus-verifier` | Altair sync committee & beacon proofs | Planned |
| `groth16-verifier` | BN254 Groth16 ZK proofs | Planned |

## License

MIT
