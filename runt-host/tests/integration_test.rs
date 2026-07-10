use runt_core::StoreManager;
use runt_host::crypto::CryptoProvider;
use runt_host::loader::VerifierLoader;
use runt_host::registry::VerifierRegistry;
use runt_host::router::VerificationRouter;
use runt_host::storage::StorageProvider;

#[test]
fn test_host_state_creation() {
    let state = runt_host::HostState::default();
    drop(state);
}

#[test]
fn test_verifier_loader_creation() {
    let store_manager = StoreManager::new();
    let loader = VerifierLoader::new(store_manager).expect("failed to create loader");
    assert_eq!(loader.component_count(), 0);
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
    let metadata = runt_host::registry::VerifierMetadata {
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
    let hash = provider.hash("keccak256", b"hello");
    assert_eq!(hash.len(), 32);
    assert_ne!(hash, vec![0u8; 32]);
}

#[test]
fn test_crypto_provider_sha256() {
    let provider = runt_host::crypto::DefaultCryptoProvider;
    let hash = provider.hash("sha256", b"hello");
    assert_eq!(hash.len(), 32);
}

#[test]
fn test_crypto_provider_unknown() {
    let provider = runt_host::crypto::DefaultCryptoProvider;
    let hash = provider.hash("unknown", b"hello");
    assert!(hash.is_empty());
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
fn test_router_creation() {
    let store_manager = StoreManager::new();
    let loader = VerifierLoader::new(store_manager).expect("failed to create loader");
    let registry = VerifierRegistry::new();
    let router = VerificationRouter::new(registry, loader);
    let result = router.verify("test", b"proof", b"inputs", b"key");
    assert!(matches!(
        result,
        runt_host::VerificationResult::Error(_)
    ));
}
