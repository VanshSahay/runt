# Runt

Portable, composable, deterministic WASM verification runtime for Ethereum proofs.

## Architecture

```
runt-abi/          C ABI constants shared between host and verifiers
runt-core/         wasmtime engine config, fuel metering, sandboxing
runt-host/         Verifier registry, loader, crypto providers, routing
runt-cli/          Command-line interface
runt-verifiers/    WASM modules implementing the verifier C ABI
  hello-verifier/  Reference verifier (dummy)
```

## How it works

Each verifier is a plain `.wasm` module exporting two functions:

```c
// Write JSON metadata to buf, return bytes written
u32 metadata(u8* buf, u32 buf_len);

// Verify a proof. Returns 0=valid, 1=invalid, 2=error
// Writes error details to error_buf on failure
u32 verify(
    u8* proof, u32 proof_len,
    u8* public_inputs, u32 public_inputs_len,
    u8* error_buf, u32 error_buf_len
);
```

Verifiers import host functions from the `"env"` module:

```c
void host_hash(u32 algorithm, u8* input, u32 input_len, u8* output);
u32  host_verify_signature(u32 scheme, u8* msg, u32 msg_len, u8* sig, u32 sig_len, u8* pk, u32 pk_len);
u32  host_pairing_check(u32 curve, u8* pairs, u32 pairs_len);
```

## Quick Start

```bash
# Build the host
cargo build --workspace

# Build verifier WASM modules
make verifiers

# List loaded verifiers
cargo run -p runt-cli -- list

# Verify a proof
cargo run -p runt-cli -- verify --proof-type hello:dummy --proof-file test.json

# Run tests
make test
```

## Adding a new verifier

1. Create a new crate in `runt-verifiers/` with `crate-type = ["cdylib"]`
2. Export `metadata` and `verify` functions with C ABI
3. Build with `cargo build --target wasm32-unknown-unknown --release`
4. Drop the `.wasm` file in `target/verifiers/`

## License

MIT
