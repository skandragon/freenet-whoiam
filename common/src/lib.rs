//! whoiam core: identity state, per-slot LWW merge, key derivation,
//! resource schemas, delegate API. Pure logic — no wasm entry points, no
//! I/O — shared by the contract, the delegate, the toolkit, and the UI.

pub mod connect;
pub mod delegate_api;
pub mod derive;
pub mod merge;
pub mod resources;
pub mod state;

/// CBOR round-trip helpers used by every consumer of these types.
pub fn to_cbor<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let mut out = vec![];
    ciborium::ser::into_writer(value, &mut out).map_err(|e| e.to_string())?;
    Ok(out)
}

pub fn from_cbor<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
    ciborium::de::from_reader(bytes).map_err(|e| e.to_string())
}
