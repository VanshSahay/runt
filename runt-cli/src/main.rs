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
    about = "WASM verification runtime for Ethereum proofs"
)]
struct Cli {
    #[arg(long, default_value = "target/verifiers")]
    verifiers_dir: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List all loaded verifiers and their capabilities
    List,
    /// Verify a proof against a verifier type
    Verify {
        #[arg(long)]
        proof_type: String,
        #[arg(long)]
        proof_file: PathBuf,
        #[arg(long)]
        public_inputs: Option<PathBuf>,
    },
    /// Print version info
    Version,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let store_manager = StoreManager::new();
    let loader = VerifierLoader::new(store_manager);
    let registry = VerifierRegistry::new();
    let mut router = VerificationRouter::new(registry, loader);

    if cli.verifiers_dir.exists() {
        match router.load_verifiers(&cli.verifiers_dir) {
            Ok(count) if count > 0 => {
                eprintln!("Loaded {count} verifier(s) from {}", cli.verifiers_dir.display());
            }
            Ok(_) => {}
            Err(e) => {
                eprintln!("Warning: failed to scan verifiers: {e}");
            }
        }
    }

    match cli.command {
        Commands::List => cmd_list(&router),
        Commands::Verify {
            proof_type,
            proof_file,
            public_inputs,
        } => cmd_verify(&router, &proof_type, &proof_file, public_inputs),
        Commands::Version => {
            println!("runt {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
    }
}

fn cmd_list(router: &VerificationRouter) -> Result<()> {
    let verifiers = router.registry().list();
    let module_count = router.loader().module_count();

    println!("WASM modules loaded: {module_count}");
    println!("Verifiers registered: {}\n", verifiers.len());

    if verifiers.is_empty() {
        println!("No verifiers loaded.");
        println!("Build: cargo build --target wasm32-unknown-unknown --release -p hello-verifier");
        println!("Then copy: cp target/wasm32-unknown-unknown/release/hello_verifier.wasm target/verifiers/");
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
        println!();
    }

    Ok(())
}

fn cmd_verify(
    router: &VerificationRouter,
    proof_type: &str,
    proof_file: &Path,
    public_inputs: Option<PathBuf>,
) -> Result<()> {
    let proof_data = read_file(proof_file)?;
    let inputs = match public_inputs {
        Some(p) => read_file(&p)?,
        None => vec![],
    };

    eprintln!(
        "Verifying {} (proof: {} bytes, inputs: {} bytes)",
        proof_type,
        proof_data.len(),
        inputs.len()
    );

    let start = std::time::Instant::now();
    let result = router.verify(proof_type, &proof_data, &inputs);
    let elapsed = start.elapsed();

    match result {
        runt_host::VerificationResult::Valid => {
            println!("status: VALID");
        }
        runt_host::VerificationResult::Invalid(reason) => {
            println!("status: INVALID");
            println!("reason: {reason}");
        }
        runt_host::VerificationResult::Error(reason) => {
            println!("status: ERROR");
            println!("reason: {reason}");
        }
    }
    println!("time: {elapsed:.2?}");

    Ok(())
}

fn read_file(path: &Path) -> Result<Vec<u8>> {
    let raw = std::fs::read(path)?;
    if path.extension().map_or(false, |ext| ext == "json") {
        let val: serde_json::Value = serde_json::from_slice(&raw)?;
        match val {
            serde_json::Value::Array(arr) => {
                Ok(arr.iter().map(|v| v.as_u64().unwrap_or(0) as u8).collect())
            }
            serde_json::Value::Object(obj) => {
                if let Some(hex_str) = obj.get("proof").and_then(|v| v.as_str()) {
                    hex::decode(hex_str.strip_prefix("0x").unwrap_or(hex_str))
                        .map_err(|e| anyhow::anyhow!("invalid hex: {e}"))
                } else if let Some(arr) = obj.get("proof_bytes") {
                    Ok(arr
                        .as_array()
                        .map(|a| a.iter().map(|v| v.as_u64().unwrap_or(0) as u8).collect())
                        .unwrap_or_default())
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
