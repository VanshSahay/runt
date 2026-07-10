.PHONY: all build verifiers test clean

all: build verifiers

build:
	cargo build --workspace

verifiers:
	@echo "Building verifier WASM components..."
	cargo build --target wasm32-unknown-unknown --release -p hello-verifier
	@mkdir -p target/verifiers
	wasm-tools component new \
		target/wasm32-unknown-unknown/release/hello_verifier.wasm \
		--adapt default \
		-o target/verifiers/hello-verifier.wasm 2>/dev/null || \
	wasm-tools component embed runt-wit/wit \
		target/wasm32-unknown-unknown/release/hello_verifier.wasm \
		-o target/verifiers/hello-verifier.wasm
	@echo "Verifier components built in target/verifiers/"

test:
	cargo test --workspace

clean:
	cargo clean
	rm -rf target/verifiers
