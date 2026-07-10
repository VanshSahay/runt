use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::{Parser, Subcommand};
use runt_core::StoreManager;
use runt_host::loader::VerifierLoader;
use runt_host::registry::VerifierRegistry;
use runt_host::router::VerificationRouter;

#[derive(Parser)]
#[command(
    name = "runt",
    about = "WASM verification runtime for Ethereum proofs",
    long_about = "Portable, composable, deterministic, and extensible WASM verification runtime.

Loads WASM component verifiers, each implementing a common Verifier interface,
and routes proof verification requests to the appropriate verifier."
)]
struct Cli {
    /// Directory containing .wasm verifier component files
    #[arg(long, default_value = "target/verifiers")]
    verifiers_dir: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List all loaded verifiers and their capabilities
    List,
    /// Verify a proof file against a specific verifier type
    Verify {
        /// Proof type identifier (e.g. "state:eip1186", "tx:receipt")
        #[arg(long)]
        proof_type: String,

        /// Path to the proof file (hex-encoded bytes file or JSON array)
        proof_file: PathBuf,

        /// Path to the public inputs file (optional, read from proof JSON if not provided)
        #[arg(long)]
        public_inputs: Option<PathBuf>,

        /// Verification key file path (optional)
        #[arg(long)]
        verification_key: Option<PathBuf>,
    },
    /// Print version and build info
    Version,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let store_manager = StoreManager::new();
    let loader = VerifierLoader::new(store_manager)?;
    let registry = VerifierRegistry::new();
    let mut router = VerificationRouter::new(registry, loader);

    if cli.verifiers_dir.exists() {
        match router.load_verifiers(&cli.verifiers_dir) {
            Ok(count) => {
                if count > 0 {
                    eprintln!("Loaded {count} verifier component(s) from {}", cli.verifiers_dir.display());
                }
            }
            Err(e) => {
                eprintln!("Warning: failed to scan verifiers directory: {e}");
            }
        }
    }

    match cli.command {
        Commands::List => cmd_list(&router),
        Commands::Verify {
            proof_type,
            proof_file,
            public_inputs,
            verification_key,
        } => cmd_verify(&router, &proof_type, &proof_file, public_inputs, verification_key),
        Commands::Version => cmd_version(),
    }
}

fn cmd_list(router: &VerificationRouter) -> Result<()> {
    let verifiers = router.registry().list();
    let component_count = router.loader().component_count();

    println!("WASM components loaded: {component_count}");
    println!("Verifiers registered: {}\n", verifiers.len());

    if verifiers.is_empty() {
        println!("No verifiers loaded. Build verifier components with:");
        println!("  cargo build --target wasm32-unknown-unknown --release -p hello-verifier");
        println!("  wasm-tools component new target/wasm32-unknown-unknown/release/hello_verifier.wasm \\");
        println!("    --adapt default -o target/verifiers/hello-verifier.wasm");
        return Ok(());
    }

    for v in verifiers {
        println!("  {:30} v{} ({})", v.proof_type_id, v.version, v.scheme);
        println!("    {}", v.description);
        if !v.curve.is_empty() {
            println!("    curve: {}", v.curve);
        }
        if v.trusted_setup_required {
            println!("    trusted setup required");
        }
        if v.supports_recursion {
            println!("    supports recursion");
        }
        if v.max_proof_size > 0 {
            let size = if v.max_proof_size >= 1_048_576 {
                format!("{} MiB", v.max_proof_size / 1_048_576)
            } else if v.max_proof_size >= 1024 {
                format!("{} KiB", v.max_proof_size / 1024)
            } else {
                format!("{} B", v.max_proof_size)
            };
            println!("    max proof size: {size}");
        }
        println!();
    }

    Ok(())
}

fn cmd_verify(
    router: &VerificationRouter,
    proof_type: &str,
    proof_file: &Path,
    public_inputs: Option<PathBuf>,
    verification_key: Option<PathBuf>,
) -> Result<()> {
    let proof_data = read_proof_file(proof_file)?;
    let inputs = match public_inputs {
        Some(p) => std::fs::read(&p)?,
        None => vec![],
    };
    let vk = match verification_key {
        Some(p) => std::fs::read(&p)?,
        None => vec![],
    };

    eprintln!(
        "Verifying {} (proof: {} bytes, inputs: {} bytes, vk: {} bytes)",
        proof_type,
        proof_data.len(),
        inputs.len(),
        vk.len()
    );

    let start = std::time::Instant::now();
    let result = router.verify(proof_type, &proof_data, &inputs, &vk);
    let elapsed = start.elapsed();

    match result {
        runt_host::VerificationResult::Valid => {
            println!("status: VALID");
            println!("verification time: {elapsed:.2?}");
        }
        runt_host::VerificationResult::Invalid(reason) => {
            println!("status: INVALID");
            println!("reason: {reason}");
            println!("verification time: {elapsed:.2?}");
        }
        runt_host::VerificationResult::Error(reason) => {
            println!("status: ERROR");
            println!("reason: {reason}");
            println!("verification time: {elapsed:.2?}");
        }
    }

    Ok(())
}

fn cmd_version() -> Result<()> {
    println!("runt {}", env!("CARGO_PKG_VERSION"));
    println!("WIT interface: runt:verifier");
    println!("supported proof types: state:eip1186, tx:receipt, consensus:altair, groth16:bn254");
    Ok(())
}

fn read_proof_file(path: &Path) -> Result<Vec<u8>> {
    let raw = std::fs::read(path)?;
    if path.extension().map_or(false, |ext| ext == "json") {
        let val: serde_json::Value = serde_json::from_slice(&raw)?;
        match val {
            serde_json::Value::Array(arr) => {
                let bytes: Vec<u8> = arr.iter().map(|v| v.as_u64().unwrap_or(0) as u8).collect();
                Ok(bytes)
            }
            serde_json::Value::Object(obj) => {
                if let Some(hex) = obj.get("proof").and_then(|v| v.as_str()) {
                    hex::decode(hex.strip_prefix("0x").unwrap_or(hex))
                        .map_err(|e| anyhow::anyhow!("invalid hex proof: {e}"))
                } else if let Some(bytes) = obj.get("proof_bytes") {
                    let arr: Vec<u8> = bytes
                        .as_array()
                        .map(|a| a.iter().map(|v| v.as_u64().unwrap_or(0) as u8).collect())
                        .unwrap_or_default();
                    Ok(arr)
                } else {
                    Ok(raw)
                }
            }
            _ => Ok(raw),
        }
    } else {
        Ok(raw)
    }
}
