//! Vendored wasm bytes and contract-address derivation.

use ed25519_dalek::VerifyingKey;
use freenet_stdlib::prelude::{ContractCode, ContractInstanceId, ContractKey, Parameters};
use whoiam_core::state::IdentityParamsV1;

pub const IDENTITY_CONTRACT_WASM: &[u8] = include_bytes!("../contracts/identity_contract.wasm");
pub const WHOIAM_DELEGATE_WASM: &[u8] = include_bytes!("../contracts/whoiam_delegate.wasm");

pub fn identity_params(pk: &VerifyingKey) -> IdentityParamsV1 {
    IdentityParamsV1 {
        version: 1,
        pubkey: *pk,
    }
}

pub fn identity_key(pk: &VerifyingKey) -> ContractKey {
    let params = whoiam_core::to_cbor(&identity_params(pk)).expect("params serialize");
    ContractKey::from_params_and_code(
        Parameters::from(params),
        &ContractCode::from(IDENTITY_CONTRACT_WASM.to_vec()),
    )
}

pub fn identity_instance_id(pk: &VerifyingKey) -> ContractInstanceId {
    *identity_key(pk).id()
}

#[cfg(target_arch = "wasm32")]
pub fn now_ms() -> u64 {
    js_sys::Date::now() as u64
}

#[cfg(not(target_arch = "wasm32"))]
pub fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn addresses_deterministic_per_identity() {
        let a = SigningKey::generate(&mut OsRng).verifying_key();
        let b = SigningKey::generate(&mut OsRng).verifying_key();
        assert_eq!(identity_key(&a), identity_key(&a));
        assert_ne!(identity_key(&a), identity_key(&b));
    }
}
