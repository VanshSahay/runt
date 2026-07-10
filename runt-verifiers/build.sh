#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TARGET_DIR="$WORKSPACE_ROOT/target/verifiers"

mkdir -p "$TARGET_DIR"

build_verifier() {
    local name="$1"
    local crate_dir="$SCRIPT_DIR/$name"

    echo "Building $name..."

    cargo build \
        --target wasm32-unknown-unknown \
        --release \
        --manifest-path "$crate_dir/Cargo.toml"

    local wasm_binary="$WORKSPACE_ROOT/target/wasm32-unknown-unknown/release/${name//-/_}.wasm"
    local wit_dir="$WORKSPACE_ROOT/runt-wit/wit"
    local output="$TARGET_DIR/$name.wasm"

    wasm-tools component new \
        "$wasm_binary" \
        --adapt "wasi_snapshot_preview1=$(
            rustup which rust-lld > /dev/null 2>&1 || true
            echo ''  # placeholder for wasi adapter if needed
        )" \
        -o "$output" \
        2>/dev/null || {
            # Fallback: embed WIT directly using wasm-tools
            wasm-tools component embed \
                "$wit_dir" \
                "$wasm_binary" \
                -o "$output"

            echo "  -> $output"
        }

    echo "  -> $output"
}

case "${1:-all}" in
    hello)
        build_verifier "hello-verifier"
        ;;
    all)
        build_verifier "hello-verifier"
        ;;
    *)
        echo "Usage: $0 {hello|all}"
        exit 1
        ;;
esac
