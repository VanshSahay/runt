#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TARGET_DIR="$WORKSPACE_ROOT/target/verifiers"
WIT_DIR="$WORKSPACE_ROOT/runt-wit/wit"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

mkdir -p "$TARGET_DIR"

build_with_wasm_tools() {
    local name="$1"
    local crate_dir="$SCRIPT_DIR/$name"

    echo -e "${YELLOW}Building $name with wasm-tools...${NC}"

    cargo build --target wasm32-unknown-unknown --release --manifest-path "$crate_dir/Cargo.toml"

    local wasm_binary="$WORKSPACE_ROOT/target/wasm32-unknown-unknown/release/${name//-/_}.wasm"
    local output="$TARGET_DIR/$name.wasm"

    wasm-tools component new "$wasm_binary" -o "$output" 2>/dev/null || {
        echo -e "${YELLOW}  wasm-tools component new failed, trying embed approach...${NC}"
        wasm-tools component embed "$WIT_DIR" "$wasm_binary" --world runt-verifier -o "$TARGET_DIR/$name-embedded.wasm" 2>/dev/null || true
        if [[ -f "$TARGET_DIR/$name-embedded.wasm" ]]; then
            wasm-tools component new "$TARGET_DIR/$name-embedded.wasm" -o "$output"
        fi
    }

    if [[ -f "$output" ]]; then
        echo -e "${GREEN}  -> $output ($(du -h "$output" | cut -f1))${NC}"
    else
        echo -e "${RED}  -> Failed to build component${NC}"
        return 1
    fi
}

build_with_cargo_component() {
    local name="$1"
    echo -e "${GREEN}Building $name with cargo-component...${NC}"

    if command -v cargo-component &>/dev/null; then
        cargo component build --release --manifest-path "$SCRIPT_DIR/$name/Cargo.toml" \
            --target wasm32-wasip2 2>/dev/null || \
        cargo component build --release --manifest-path "$SCRIPT_DIR/$name/Cargo.toml"
    else
        echo -e "${RED}cargo-component not found. Install with:${NC}"
        echo "  cargo install cargo-component"
        return 1
    fi
}

case "${1:-all}" in
    hello)
        if command -v cargo-component &>/dev/null; then
            build_with_cargo_component "hello-verifier"
        else
            build_with_wasm_tools "hello-verifier"
        fi
        ;;
    state)
        build_with_wasm_tools "state-verifier"
        ;;
    all)
        for verifier in hello-verifier state-verifier tx-verifier consensus-verifier groth16-verifier; do
            if command -v cargo-component &>/dev/null && [[ "$verifier" == "hello-verifier" ]]; then
                build_with_cargo_component "$verifier" || true
            else
                build_with_wasm_tools "$verifier" || true
            fi
        done
        ;;
    *)
        echo "Usage: $0 {hello|state|all}"
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}Verifier components in: $TARGET_DIR${NC}"
ls -la "$TARGET_DIR"/*.wasm 2>/dev/null || echo "  (no components built)"
