use move_binary_format::errors::PartialVMResult;
use move_core_types::gas_algebra::InternalGas;
use move_vm_runtime::native_functions::NativeContext;
use move_vm_types::{
    loaded_data::runtime_types::Type,
    natives::function::NativeResult,
    pop_arg,
    values::{Struct, Value, Vector},
};

use prost::Message;

use ibc::{
    clients::tendermint::types::error::{Error as LcError, IntoResult},
    clients::tendermint::types::{ConsensusState, Header as TmHeader},
    core::{
        client::types::error::ClientError, commitment_types::commitment::CommitmentRoot,
        host::types::identifiers::ChainId,
    },
    primitives::{proto::Any, ToVec},
};
use smallvec::smallvec;
use std::{collections::VecDeque, error::Error, str::FromStr, time::Duration};
use tendermint::crypto::default::Sha256;
use tendermint::{merkle::MerkleHash, Hash, Time};
use tendermint_light_client_verifier::{
    options::Options,
    types::{TrustThreshold, TrustedBlockState, UntrustedBlockState},
    ProdVerifier, Verifier,
};
use tracing::instrument;

use tendermint::crypto::Sha256 as Sha256Trait;
#[derive(Clone)]
pub struct TendermintLightClientCostParams {
    pub tendermint_state_proof_cost_base: InternalGas,
    pub tendermint_verify_lc_cost_base: InternalGas,
    pub tendermint_extract_consensus_state_base: InternalGas,
}

#[instrument(level = "trace", skip_all, err)]
pub fn tendermint_state_proof(
    context: &mut NativeContext,
    ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    todo!()
}

#[instrument(level = "trace", skip_all, err)]
pub fn tendermint_verify_lc(
    context: &mut NativeContext,
    ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    assert!(args.len() == 4);
    // assert!(ty_args.len() == 0);
    let header = pop_arg!(args, Vector).to_vec_u8()?;
    let commitment_root = pop_arg!(args, Vector).to_vec_u8()?;
    let next_validators_hash = pop_arg!(args, Vector).to_vec_u8()?;
    let timestamp = pop_arg!(args, Vector).to_vec_u8()?;

    let Ok(any) = Any::decode(&mut header.as_slice()) else {
        return Ok(NativeResult::err(context.gas_used(), 1));
    };

    let Ok(header) = TmHeader::try_from(any) else {
        return Ok(NativeResult::err(context.gas_used(), 1));
    };

    let Ok(timestamp) = String::from_utf8(timestamp) else {
        return Ok(NativeResult::err(context.gas_used(), 1));
    };

    let Ok(next_validators_hash) =
        Hash::from_bytes(tendermint::hash::Algorithm::Sha256, &next_validators_hash)
    else {
        return Ok(NativeResult::err(context.gas_used(), 1));
    };

    let root = CommitmentRoot::from_bytes(&commitment_root);

    let Ok(timestamp) = Time::from_str(&timestamp) else {
        return Ok(NativeResult::err(context.gas_used(), 1));
    };

    let cs = ConsensusState {
        next_validators_hash,
        root,
        timestamp,
    };

    // move those data to init lc method
    let five_year: u64 = 5 * 365 * 24 * 60 * 60;
    let options = Options {
        clock_drift: Duration::new(40, 0),
        trust_threshold: TrustThreshold::ONE_THIRD,
        trusting_period: Duration::new(five_year, 0),
    };

    // TODO: Move chain_id to init lc method
    let chain_id = ChainId::new("ibc-0").unwrap();
    let result = verify_header_lc::<Sha256>(
        &chain_id,
        &cs,
        &header,
        &options,
        ProdVerifier::default(),
        timestamp,
    )
    .is_ok();
    Ok(NativeResult::ok(
        context.gas_used(),
        smallvec![Value::bool(result)],
    ))
}

// TODO: should we move this function into tendermint_verify_lc
#[instrument(level = "trace", skip_all, err)]
pub fn extract_consensus_state(
    context: &mut NativeContext,
    ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    let header = pop_arg!(args, Vector).to_vec_u8()?;

    let Ok(any) = Any::decode(&mut header.as_slice()) else {
        return Ok(NativeResult::err(context.gas_used(), 1));
    };

    let Ok(header) = TmHeader::try_from(any) else {
        return Ok(NativeResult::err(context.gas_used(), 1));
    };

    let timestamp = header.timestamp().to_string().to_vec();
    let next_validators_hash = header
        .signed_header
        .header
        .next_validators_hash
        .as_bytes()
        .to_vec();
    let root = header.signed_header.header.app_hash.as_bytes().to_vec();
    let height = header.height().revision_height();

    let value = vec![
        Value::u64(height),
        Value::vector_u8(timestamp),
        Value::vector_u8(next_validators_hash),
        Value::vector_u8(root),
    ];
    let value = Value::struct_(Struct::pack(value));
    Ok(NativeResult::ok(context.gas_used(), smallvec![value]))
}

// verify tendermint(cometBFT) without implement ExtClientValidationContext.
// we only verify with the latest consensus state
// TODO: make it fit with verify_header in ibc-rs
pub fn verify_header_lc<H: MerkleHash + Sha256Trait + Default>(
    chain_id: &ChainId,
    trusted_consensus_state: &ConsensusState,
    header: &TmHeader,
    options: &Options,
    verifier: impl Verifier,
    timestamp: Time,
) -> Result<(), Box<dyn Error>> {
    header.validate_basic::<H>()?;

    // TODO: make it more sense
    // header.verify_chain_id_version_matcmap_err(op)hes_height(chain_id)?;
    {
        let trusted_state = {
            header.check_trusted_next_validator_set::<H>(
                &trusted_consensus_state.next_validators_hash,
            )?;
            TrustedBlockState {
                chain_id: &chain_id
                    .as_str()
                    .try_into()
                    .map_err(|e| ClientError::Other {
                        description: format!("failed to parse chain id: {}", e),
                    })?,
                header_time: trusted_consensus_state.timestamp(),
                height: header
                    .trusted_height
                    .revision_height()
                    .try_into()
                    .map_err(|_| ClientError::ClientSpecific {
                        description: LcError::InvalidHeaderHeight {
                            height: header.trusted_height.revision_height(),
                        }
                        .to_string(),
                    })?,
                next_validators: &header.trusted_next_validator_set,
                next_validators_hash: trusted_consensus_state.next_validators_hash,
            }
        };

        let untrusted_state = UntrustedBlockState {
            signed_header: &header.signed_header,
            validators: &header.validator_set,
            // NB: This will skip the
            // VerificationPredicates::next_validators_match check for the
            // untrusted state.
            next_validators: None,
        };

        let now = timestamp;
        verifier
            .verify_update_header(untrusted_state, trusted_state, options, now)
            .into_result()?;
    }
    Ok(())
}
