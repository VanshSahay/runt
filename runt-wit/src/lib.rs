pub mod bindings;

pub use bindings::exports::runt::verifier::verifier::{
    Guest, VerificationStatus, VerifierMetadata,
};
pub use bindings::runt::verifier::host_crypto;
pub use bindings::runt::verifier::host_storage;

#[macro_export]
macro_rules! export_verifier {
    ($ty:ident) => {
        $crate::bindings::exports::runt::verifier::verifier::__export_runt_verifier_verifier_cabi!(
            $ty with_types_in $crate::bindings
        );
    };
}
