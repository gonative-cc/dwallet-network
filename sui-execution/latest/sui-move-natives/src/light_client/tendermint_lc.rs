use move_binary_format::errors::PartialVMResult;
use move_core_types::{gas_algebra::InternalGas, u256::U256};
use move_vm_runtime::native_functions::NativeContext;
use move_vm_types::{
    loaded_data::runtime_types::Type,
    natives::function::NativeResult,
    pop_arg,
    values::{Struct, Value, Vector},
};

use std::{collections::VecDeque, str::from_utf8};

use ibc::{
    clients::tendermint::types::{proto::v1::Header as RawHeader, TENDERMINT_HEADER_TYPE_URL},
    core::{
        commitment_types::{
            commitment::{CommitmentPrefix, CommitmentProofBytes, CommitmentRoot},
            merkle::{MerklePath, MerkleProof},
            proto::ics23::{CommitmentProof, HostFunctionsManager},
            specs::ProofSpecs,
        },
    },
    primitives::proto::Protobuf,
};

use ibc_proto::google::protobuf::Any;

use ibc::{
    clients::tendermint::types::error::{IntoResult, TendermintClientError as LcError},
    clients::tendermint::types::{ConsensusState, Header as TmHeader},
    core::{client::types::error::ClientError, host::types::identifiers::ChainId},
};
use smallvec::smallvec;
use std::{error::Error, str::FromStr, time::Duration};
use tendermint::{crypto::default::Sha256, trust_threshold};
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

enum NativeError {
    PrefixInvalid = 0,
    PathInvalid,
    CommitmentProofInvalid,
    MerkleProofInvalid,
    HeaderInvalid,
    TimestampInvalid,
    NextValidatorsHashInvalid,
    TypeInvalid,
}

fn state_proof_type_check(
    value: Vec<u8>,
    path: Vec<u8>,
    prefix: Vec<u8>,
    root: Vec<u8>,
    proof: Vec<u8>,
) -> Result<(Vec<u8>, MerklePath, MerkleProof, CommitmentRoot), NativeError> {
    let merkle_path = MerklePath::new(vec![prefix.into(), path.into()]);

    let Ok(proof_bytes) = CommitmentProofBytes::try_from(proof) else {
        return Err(NativeError::CommitmentProofInvalid);
    };

    let Ok(merkle_proof) = MerkleProof::try_from(&proof_bytes) else {
        return Err(NativeError::MerkleProofInvalid);
    };

    let root = CommitmentRoot::from_bytes(&root);

    Ok((value, merkle_path, merkle_proof, root))
}

#[instrument(level = "trace", skip_all, err)]
pub fn tendermint_state_proof(
    context: &mut NativeContext,
    ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    assert!(args.len() == 5);
    assert!(ty_args.len() == 0);

    let value = pop_arg!(args, Vector).to_vec_u8()?;
    let path = pop_arg!(args, Vector).to_vec_u8()?;
    let prefix = pop_arg!(args, Vector).to_vec_u8()?;
    let root = pop_arg!(args, Vector).to_vec_u8()?;
    let proof = pop_arg!(args, Vector).to_vec_u8()?;

    match state_proof_type_check(value, path, prefix, root, proof) {
        Ok((value, merkle_path, merkle_proof, root)) => {
            let verified = merkle_proof
                .verify_membership::<HostFunctionsManager>(
                    &ProofSpecs::cosmos(),
                    root.into(),
                    merkle_path,
                    value,
                    0,
                )
                .is_ok();

            Ok(NativeResult::ok(
                context.gas_used(),
                smallvec![Value::bool(verified)],
            ))
        }
        Err(err) => Ok(NativeResult::err(context.gas_used(), err as u64)),
    }
}

fn tendermint_verify_type_check(
    header: Vec<u8>,
    commitment_root: Vec<u8>,
    next_validators_hash: Vec<u8>,
    timestamp: Vec<u8>,
) -> Result<(TmHeader, ConsensusState, Time), NativeError> {
    let raw_header: RawHeader = Protobuf::<RawHeader>::decode_vec(header.as_ref()).unwrap();
    
    let header: TmHeader = raw_header.into();
    // let header = TmHeader::try_from(any).unwrap();
    // let Ok(header) = TmHeader::try_from(any) else {
    //     return Err(NativeError::HeaderInvalid);
    // };
    let Ok(timestamp) = String::from_utf8(timestamp) else {
        return Err(NativeError::TimestampInvalid);
    };

    let Ok(next_validators_hash) =
        Hash::from_bytes(tendermint::hash::Algorithm::Sha256, &next_validators_hash)
    else {
        return Err(NativeError::NextValidatorsHashInvalid);
    };

    let root = CommitmentRoot::from_bytes(&commitment_root);

    let Ok(timestamp) = Time::from_str(&timestamp) else {
        return Err(NativeError::TimestampInvalid);
    };

    let cs = ConsensusState {
        next_validators_hash,
        root,
        timestamp,
    };

    Ok((header, cs, timestamp))
}

fn tendermint_options(
    clock_drift: U256,
    trust_threashold: U256,
    trusting_period: U256,
) -> Result<Options, NativeError> {
    let Ok(clock_drift) = clock_drift.try_into() else {
        return Err(NativeError::TypeInvalid);
    };

    let Ok(trust_threshold) = TryInto::<u64>::try_into(trust_threashold) else {
        return Err(NativeError::TypeInvalid);
    };

    let Ok(trusting_period) = trusting_period.try_into() else {
        return Err(NativeError::TypeInvalid);
    };

    let trust_threshold = match trust_threshold {
        0 => TrustThreshold::ONE_THIRD,
        1 => TrustThreshold::TWO_THIRDS,
        _ => return Err(NativeError::TypeInvalid),
    };

    let options = Options {
        clock_drift: Duration::new(clock_drift, 0),
        trust_threshold,
        trusting_period: Duration::new(trusting_period, 0),
    };

    Ok(options)
}

// TODO: remove trace and add document for this funciton.
#[instrument(level = "trace", skip_all, err)]
pub fn tendermint_verify_lc(
    context: &mut NativeContext,
    ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    assert!(args.len() == 8);
    assert!(ty_args.len() == 0);

    let header = pop_arg!(args, Vector).to_vec_u8()?;
    let commitment_root = pop_arg!(args, Vector).to_vec_u8()?;
    let next_validators_hash = pop_arg!(args, Vector).to_vec_u8()?;
    let timestamp = pop_arg!(args, Vector).to_vec_u8()?;

    let trusting_period = pop_arg!(args, U256);
    let trust_threashold = pop_arg!(args, U256);
    let clock_drift = pop_arg!(args, U256);
    let chain_id = pop_arg!(args, Vector).to_vec_u8()?;

    let options = match tendermint_options(clock_drift, trust_threashold, trusting_period) {
        Ok(options) => options,
        Err(err) => return Ok(NativeResult::err(context.gas_used(), err as u64)),
    };

    let chain_id_str = match std::str::from_utf8(&chain_id) {
        Ok(s) => s,
        _  => {
            return Ok(NativeResult::err(context.gas_used(), 0));
        }
    };

    let chain_id = ChainId::new(chain_id_str).unwrap();

    match tendermint_verify_type_check(header, commitment_root, next_validators_hash, timestamp) {
        Ok((header, cs, timestamp)) => {
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
        Err(err) => Ok(NativeResult::err(context.gas_used(), err as u64)),
    }
}

// TODO: should we move this function into tendermint_verify_lc
// TODO: remove trace and add document for this function.
#[instrument(level = "trace", skip_all, err)]
pub fn extract_consensus_state(
    context: &mut NativeContext,
    ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    assert!(args.len() == 1);
    let header = pop_arg!(args, Vector).to_vec_u8()?;
    let any = Any {
        type_url: TENDERMINT_HEADER_TYPE_URL.to_string(),
        value: header,
    };

    let Ok(header) = TmHeader::try_from(any) else {
        return Ok(NativeResult::err(
            context.gas_used(),
            NativeError::HeaderInvalid as u64,
        ));
    };

    let timestamp = header.timestamp().unwrap().encode_vec();

    let next_validators_hash = header
        .signed_header
        .header
        .next_validators_hash
        .as_bytes()
        .to_vec();
    let root = header.signed_header.header.app_hash.as_bytes().to_vec();
    let height = header.height().revision_height();

    Ok(NativeResult::ok(
        context.gas_used(),
        smallvec![pack_consensus_state(
            height,
            timestamp,
            next_validators_hash,
            root
        )],
    ))
}

pub fn pack_consensus_state(
    height: u64,
    timestamp: Vec<u8>,
    next_validators_hash: Vec<u8>,
    root: Vec<u8>,
) -> Value {
    let value = vec![
        Value::u64(height),
        Value::vector_u8(timestamp),
        Value::vector_u8(next_validators_hash),
        Value::vector_u8(root),
    ];
    Value::struct_(Struct::pack(value))
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
                chain_id: &chain_id.as_str().try_into().map_err(|e| {
                    ClientError::ClientSpecific {
                        description: format!("failed to parse chain id: {}", e),
                    }
                })?,
                header_time: trusted_consensus_state.timestamp(),
                height: header
                    .trusted_height
                    .revision_height()
                    .try_into()
                    .map_err(|_| ClientError::ClientSpecific {
                        description: LcError::InvalidHeaderHeight(
                            header.trusted_height.revision_height(),
                        )
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
