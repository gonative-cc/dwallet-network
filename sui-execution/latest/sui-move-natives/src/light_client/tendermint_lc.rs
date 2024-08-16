use move_binary_format::errors::PartialVMResult;
use move_core_types::gas_algebra::InternalGas;
use move_vm_runtime::native_functions::NativeContext;
use move_vm_types::{
    loaded_data::runtime_types::Type,
    natives::function::NativeResult,
    pop_arg,
    values::{Value, Vector, VectorRef},
};

use ibc::{
    apps::transfer::types::proto,
    clients::tendermint::types::error::{Error as LcError, IntoResult},
    clients::tendermint::{
        client_state::{verify_header, verify_membership},
        types::{proto::v1::Header, ConsensusState, Header as TmHeader},
    },
    core::{
        client::types::error::ClientError,
        commitment_types::{
            commitment::{CommitmentPrefix, CommitmentProofBytes, CommitmentRoot},
            proto::ics23::{commitment_proof, CommitmentProof, HostFunctionsManager},
            specs::ProofSpecs,
        },
        host::types::{
            identifiers::{ChainId, ClientId, PortId},
            path::{ClientStatePath, CommitmentPath, Path, PortPath},
        },
    },
    primitives::{
        proto::{Any, Protobuf},
        serializers::serialize,
        Timestamp, ToVec,
    },
};
use smallvec::smallvec;
use std::{
    collections::VecDeque,
    error::Error,
    io::{Chain, Read},
    str::FromStr,
    time::Duration,
};
use tendermint::crypto::default::Sha256;
use tendermint::{merkle::MerkleHash, Hash, Time};
use tendermint_light_client_verifier::{
    options::Options,
    types::{TrustThreshold, TrustedBlockState, UntrustedBlockState},
    ProdVerifier, Verifier,
};

use tendermint::crypto::Sha256 as Sha256Trait;
#[derive(Clone)]
pub struct TendermintLightClientCostParams {
    pub tendermint_state_proof_cost_base: InternalGas,
    pub tendermint_init_lc_cost_base: InternalGas,
    pub tendermint_verify_lc_cost_base: InternalGas,
    pub tendermint_update_ls_cost_base: InternalGas,
}

pub fn tendermint_state_proof(
    context: &mut NativeContext,
    ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    todo!()
}

pub fn tendermint_init_lc(
    context: &mut NativeContext,
    ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    todo!()
}

pub fn tendermint_verify_lc(
    context: &mut NativeContext,
    ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    let timestamp = pop_arg!(args, Vector).to_vec_u8().unwrap();
    let next_validators_hash = pop_arg!(args, Vector).to_vec_u8().unwrap();
    let commitment_root = pop_arg!(args, Vector).to_vec_u8().unwrap();

    // covert byte to header
    let header = pop_arg!(args, Vector).to_vec_u8().unwrap();

    let type_url = "/ibc.lightclients.tendermint.v1.Header".to_string();
    let any = Any {
        type_url,
        value: header,
    };

    let header = TmHeader::try_from(any).unwrap();

    let timestamp = String::from_utf8(timestamp).unwrap();

    let cs = ConsensusState {
        next_validators_hash: Hash::from_bytes(
            tendermint::hash::Algorithm::Sha256,
            &next_validators_hash,
        )
        .unwrap(),
        root: CommitmentRoot::from_bytes(&commitment_root),
        timestamp: Time::from_str(&timestamp).unwrap(),
    };

    let five_year: u64 = 5 * 365 * 24 * 60 * 60;
    let options = Options {
        clock_drift: Duration::new(40, 0),
        trust_threshold: TrustThreshold::ONE_THIRD,
        trusting_period: Duration::new(five_year, 0),
    };

    let chain_id = ChainId::new("mychain-3").unwrap();
    let result =
        verify_header_lc::<Sha256>(&chain_id, &cs, &header, &options, ProdVerifier::default(), Time::from_str(&timestamp).unwrap());
    Ok(NativeResult::ok(
        context.gas_used(),
        smallvec![Value::bool(true)],
    ))
}

pub fn tendermint_update_lc(
    context: &mut NativeContext,
    ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    todo!()
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
) -> Result<bool, Box<dyn Error>> {
    
    header.validate_basic::<H>()?;

    // TODO: make it more sense
    // header.verify_chain_id_version_matches_height(chain_id)?;
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

        let now =timestamp;
        verifier
            .verify_update_header(untrusted_state, trusted_state, options, now)
            .into_result()?;
    }
    Ok(true)
}
