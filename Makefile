.PHONY: all build verifiers test clean

all: build verifiers

build:
	cargo build --workspace

verifiers:
	@mkdir -p target/verifiers
	@for v in hello-verifier state-verifier tx-verifier consensus-verifier groth16-verifier; do \
		echo "Building $$v..."; \
		cargo build --target wasm32-unknown-unknown --release -p $$v; \
		cp target/wasm32-unknown-unknown/release/$$(echo $$v | tr '-' '_').wasm target/verifiers/; \
	done
	@echo ""
	@echo "Verifiers built:"
	@ls -lh target/verifiers/

test:
	cargo test -p runt-core -p runt-host -p runt-cli -- --test-threads=1

clean:
	cargo clean
	rm -rf target/verifiers
