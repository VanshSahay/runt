use runt_host::crypto::CryptoProvider;
use runt_host::loader::VerifierLoader;
use runt_host::registry::VerifierRegistry;
use runt_host::router::VerificationRouter;
use runt_host::storage::StorageProvider;
use runt_core::StoreManager;

#[test]
fn test_verifier_loader_creation() {
    let store_manager = StoreManager::new();
    let loader = VerifierLoader::new(store_manager);
    assert_eq!(loader.module_count(), 0);
}

#[test]
fn test_verifier_registry_empty() {
    let registry = VerifierRegistry::new();
    assert!(registry.is_empty());
    assert_eq!(registry.len(), 0);
}

#[test]
fn test_verifier_registry_register() {
    let mut registry = VerifierRegistry::new();
    let metadata = runt_host::types::VerifierMetadata {
        proof_type_id: "test:dummy".into(),
        version: "0.1.0".into(),
        curve: String::new(),
        scheme: "dummy".into(),
        supports_recursion: false,
        trusted_setup_required: false,
        max_proof_size: 0,
        description: "test verifier".into(),
    };
    registry.register(metadata);
    assert_eq!(registry.len(), 1);
    assert!(registry.get("test:dummy").is_some());
}

#[test]
fn test_crypto_provider_keccak256() {
    let provider = runt_host::crypto::DefaultCryptoProvider;
    let hash = provider.keccak256(b"hello");
    assert_ne!(hash, [0u8; 32]);
}

#[test]
fn test_crypto_provider_sha256() {
    let provider = runt_host::crypto::DefaultCryptoProvider;
    let hash = provider.sha256(b"hello");
    assert_ne!(hash, [0u8; 32]);
}

#[test]
fn test_storage_provider() {
    let mut storage = runt_host::storage::InMemoryStorage::new();
    storage.insert_verification_key("key1".into(), vec![1, 2, 3]);
    let key = storage.get_verification_key("key1").expect("key should exist");
    assert_eq!(key, vec![1, 2, 3]);
    assert!(storage.get_verification_key("nonexistent").is_err());
}

#[test]
fn test_capability_index() {
    let mut registry = VerifierRegistry::new();
    let metadata = runt_host::types::VerifierMetadata {
        proof_type_id: "groth16:bn254".into(),
        version: "0.1.0".into(),
        curve: "bn254".into(),
        scheme: "groth16".into(),
        supports_recursion: false,
        trusted_setup_required: true,
        max_proof_size: 8192,
        description: "test".into(),
    };
    registry.register(metadata);
    let by_curve = registry.find_by_capability("curve", "bn254");
    assert_eq!(by_curve.len(), 1);
    assert_eq!(by_curve[0].proof_type_id, "groth16:bn254");
}

#[test]
fn test_router_creation() {
    let store_manager = StoreManager::new();
    let loader = VerifierLoader::new(store_manager);
    let registry = VerifierRegistry::new();
    let router = VerificationRouter::new(registry, loader);
    let result = router.verify("test", b"proof", b"inputs");
    assert!(matches!(result, runt_host::VerificationResult::Error(_)));
}
