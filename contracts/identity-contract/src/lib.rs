//! Thin contract shell over `whoiam_core`: a per-identity slot map with
//! LWW merge and a destroy-forever marker. All checks live in whoiam-core;
//! this file deserializes, applies the merge with the host clock, and
//! implements the four `ContractInterface` entry points.

use ciborium::{de::from_reader, ser::into_writer};
use freenet_stdlib::prelude::*;

use whoiam_core::merge::{delta_since, merge_state, summarize, validate_full, SummaryV1};
use whoiam_core::state::{IdentityParamsV1, IdentityStateV1};

fn now_ms() -> u64 {
    freenet_stdlib::time::now().timestamp_millis().max(0) as u64
}

fn deser<T: serde::de::DeserializeOwned>(bytes: &[u8], what: &str) -> Result<T, ContractError> {
    from_reader::<T, &[u8]>(bytes).map_err(|e| ContractError::Deser(format!("{what}: {e}")))
}

fn ser<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, ContractError> {
    let mut out = vec![];
    into_writer(value, &mut out).map_err(|e| ContractError::Deser(e.to_string()))?;
    Ok(out)
}

fn parse_state(bytes: &[u8]) -> Result<IdentityStateV1, ContractError> {
    if bytes.is_empty() {
        Ok(IdentityStateV1::default())
    } else {
        deser(bytes, "state")
    }
}

#[allow(dead_code)]
struct Contract;

#[contract]
impl ContractInterface for Contract {
    fn validate_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        _related: RelatedContracts<'static>,
    ) -> Result<ValidateResult, ContractError> {
        let bytes = state.as_ref();
        if bytes.is_empty() {
            return Ok(ValidateResult::Valid);
        }
        let state: IdentityStateV1 = deser(bytes, "state")?;
        let params: IdentityParamsV1 = deser(parameters.as_ref(), "parameters")?;
        if params.version != 1 {
            return Ok(ValidateResult::Invalid);
        }
        match validate_full(&state, &params.pubkey, now_ms()) {
            Ok(()) => Ok(ValidateResult::Valid),
            // ValidateResult::Invalid carries no reason; log it or it dies here.
            Err(e) => {
                freenet_stdlib::log::info(&format!("invalid state: {e}"));
                Ok(ValidateResult::Invalid)
            }
        }
    }

    fn update_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        data: Vec<UpdateData<'static>>,
    ) -> Result<UpdateModification<'static>, ContractError> {
        let params: IdentityParamsV1 = deser(parameters.as_ref(), "parameters")?;
        if params.version != 1 {
            return Err(ContractError::InvalidUpdateWithInfo {
                reason: format!("unsupported params version {}", params.version),
            });
        }
        let mut current = parse_state(state.as_ref())?;
        let now = now_ms();
        for update in data {
            // State and delta are the same shape: a (possibly partial)
            // IdentityStateV1 to fold in. Unknown variants (#[non_exhaustive])
            // are rejected, not skipped — acknowledging an update we didn't
            // apply would be a lie (freebird convention, all five contracts).
            let incoming: IdentityStateV1 = match &update {
                UpdateData::State(s) => parse_state(s.as_ref())?,
                UpdateData::Delta(d) => parse_state(d.as_ref())?,
                UpdateData::StateAndDelta { state, .. } => parse_state(state.as_ref())?,
                _ => return Err(ContractError::InvalidUpdate),
            };
            merge_state(&mut current, &incoming, &params.pubkey, now)
                .map_err(|e| ContractError::InvalidUpdateWithInfo { reason: e })?;
        }
        Ok(UpdateModification::valid(State::from(ser(&current)?)))
    }

    fn summarize_state(
        _parameters: Parameters<'static>,
        state: State<'static>,
    ) -> Result<StateSummary<'static>, ContractError> {
        let state = parse_state(state.as_ref())?;
        Ok(StateSummary::from(ser(&summarize(&state))?))
    }

    fn get_state_delta(
        _parameters: Parameters<'static>,
        state: State<'static>,
        summary: StateSummary<'static>,
    ) -> Result<StateDelta<'static>, ContractError> {
        let state = parse_state(state.as_ref())?;
        let summary: SummaryV1 = if summary.as_ref().is_empty() {
            SummaryV1::default()
        } else {
            deser(summary.as_ref(), "summary")?
        };
        Ok(StateDelta::from(ser(&delta_since(&state, &summary))?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use whoiam_core::state::{sign_destroy, sign_slot};

    // The native freenet_stdlib::time stub returns an arbitrary value (it
    // transmutes uninitialized memory — freenet-stdlib 0.8.5 src/time.rs),
    // so test timestamps must be small: after the `.max(0)` clamp, any
    // possible clock value accepts them as past, never far-future.
    fn wall_now() -> u64 {
        10_000
    }

    fn params_bytes(sk: &SigningKey) -> Vec<u8> {
        whoiam_core::to_cbor(&IdentityParamsV1 {
            version: 1,
            pubkey: sk.verifying_key(),
        })
        .unwrap()
    }

    fn state_bytes(state: &IdentityStateV1) -> Vec<u8> {
        whoiam_core::to_cbor(state).unwrap()
    }

    #[test]
    fn empty_state_valid() {
        let sk = SigningKey::generate(&mut OsRng);
        let r = Contract::validate_state(
            Parameters::from(params_bytes(&sk)),
            State::from(Vec::<u8>::new()),
            RelatedContracts::default(),
        )
        .unwrap();
        assert!(matches!(r, ValidateResult::Valid));
    }

    #[test]
    fn valid_state_accepted_forged_rejected() {
        let sk = SigningKey::generate(&mut OsRng);
        let mut state = IdentityStateV1::default();
        state
            .slots
            .insert("profile".into(), sign_slot(&sk, "profile", wall_now(), b"p".to_vec()));
        let r = Contract::validate_state(
            Parameters::from(params_bytes(&sk)),
            State::from(state_bytes(&state)),
            RelatedContracts::default(),
        )
        .unwrap();
        assert!(matches!(r, ValidateResult::Valid));

        // Same state validated against a DIFFERENT identity's params.
        let other = SigningKey::generate(&mut OsRng);
        let r = Contract::validate_state(
            Parameters::from(params_bytes(&other)),
            State::from(state_bytes(&state)),
            RelatedContracts::default(),
        )
        .unwrap();
        assert!(matches!(r, ValidateResult::Invalid));
    }

    #[test]
    fn update_merges_lww() {
        let sk = SigningKey::generate(&mut OsRng);
        let now = wall_now();
        let mut old = IdentityStateV1::default();
        old.slots
            .insert("profile".into(), sign_slot(&sk, "profile", now - 10, b"old".to_vec()));
        let mut new = IdentityStateV1::default();
        new.slots
            .insert("profile".into(), sign_slot(&sk, "profile", now, b"new".to_vec()));

        let result = Contract::update_state(
            Parameters::from(params_bytes(&sk)),
            State::from(state_bytes(&old)),
            vec![UpdateData::Delta(StateDelta::from(state_bytes(&new)))],
        )
        .unwrap();
        let merged: IdentityStateV1 =
            whoiam_core::from_cbor(result.new_state.as_ref().unwrap().as_ref()).unwrap();
        assert_eq!(merged.slots["profile"].bytes, b"new");
    }

    #[test]
    fn destroy_collapses() {
        let sk = SigningKey::generate(&mut OsRng);
        let now = wall_now();
        let mut old = IdentityStateV1::default();
        old.slots
            .insert("profile".into(), sign_slot(&sk, "profile", now, b"x".to_vec()));
        let mut kill = IdentityStateV1::default();
        kill.destroyed = Some(sign_destroy(&sk, now));

        let result = Contract::update_state(
            Parameters::from(params_bytes(&sk)),
            State::from(state_bytes(&old)),
            vec![UpdateData::Delta(StateDelta::from(state_bytes(&kill)))],
        )
        .unwrap();
        let merged: IdentityStateV1 =
            whoiam_core::from_cbor(result.new_state.as_ref().unwrap().as_ref()).unwrap();
        assert!(merged.slots.is_empty());
        assert!(merged.destroyed.is_some());
    }
}
