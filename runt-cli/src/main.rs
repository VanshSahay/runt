use anyhow::Result;
use clap::{Parser, Subcommand};
use runt_core::StoreManager;
use runt_host::loader::VerifierLoader;
use runt_host::registry::VerifierRegistry;
use runt_host::router::VerificationRouter;

#[derive(Parser)]
#[command(name = "runt", about = "WASM verification runtime for Ethereum proofs")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List all loaded verifiers and their capabilities
    List,
    /// Verify a proof
    Verify {
        /// Proof type (state, tx, consensus, groth16)
        #[arg(long)]
        proof_type: String,

        /// Path to proof JSON file
        proof_file: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let store_manager = StoreManager::new();
    let loader = VerifierLoader::new(store_manager)?;
    let registry = VerifierRegistry::new();
    let router = VerificationRouter::new(registry, loader);

    match cli.command {
        Commands::List => {
            println!("Verifiers loaded: {}", router.registry().len());
            for verifier in router.registry().list() {
                println!("  {} v{} — {}", verifier.proof_type_id, verifier.version, verifier.description);
            }
            println!();
            println!("WASM components loaded: {}", router.loader().component_count());
        }
        Commands::Verify {
            proof_type,
            proof_file,
        } => {
            println!("Verifying {proof_type} proof from {proof_file}...");
            println!("Status: not yet implemented");
        }
    }

    Ok(())
}
