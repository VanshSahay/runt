.PHONY: all build verifiers test clean run-list run-verify

all: build verifiers

build:
	cargo build --workspace

verifiers:
	cargo build --target wasm32-unknown-unknown --release -p hello-verifier
	@mkdir -p target/verifiers
	cp target/wasm32-unknown-unknown/release/hello_verifier.wasm target/verifiers/

test:
	cargo test -p runt-core -p runt-host -p runt-cli

run-list: verifiers
	cargo run -p runt-cli -- list

clean:
	cargo clean
	rm -rf target/verifiers
