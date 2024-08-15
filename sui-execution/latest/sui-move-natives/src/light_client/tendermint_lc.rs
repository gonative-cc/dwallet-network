use move_binary_format::errors::PartialVMResult;
use move_core_types::gas_algebra::InternalGas;
use move_vm_runtime::native_functions::NativeContext;
use move_vm_types::{
    loaded_data::runtime_types::Type,
    natives::function::NativeResult,
    pop_arg,
    values::{Value, Vector, VectorRef},
};

use smallvec::smallvec;
use tendermint::{Hash, Time};
use core::time;
use std::{collections::VecDeque, io::Read, str::FromStr};

use ibc::{
    apps::transfer::types::proto, clients::tendermint::{client_state::{verify_header, verify_membership}, types::{proto::v1::Header, ConsensusState, Header as TmHeader}}, core::{
        commitment_types::{
            commitment::{CommitmentPrefix, CommitmentProofBytes, CommitmentRoot},
            proto::ics23::{commitment_proof, CommitmentProof, HostFunctionsManager},
            specs::ProofSpecs,
        },
        host::types::{
            identifiers::{ClientId, PortId},
            path::{ClientStatePath, CommitmentPath, Path, PortPath},
        },
    }, primitives::{proto::{Any, Protobuf}, serializers::serialize, Timestamp, ToVec}
};

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
        value: header
    };  

    let header = TmHeader::try_from(any).unwrap();

    let timestamp = String::from_utf8(timestamp).unwrap();
    
    let cs = ConsensusState {
        next_validators_hash: Hash::from_bytes(tendermint::hash::Algorithm::Sha256, &next_validators_hash).unwrap(),
        root: CommitmentRoot::from_bytes(&commitment_root),
        timestamp: Time::from_str(&timestamp).unwrap()
    };

    // verify_header(ctx, header, client_id, chain_id, options, verifier)
    
    Ok(NativeResult::ok(context.gas_used(), smallvec![Value::bool(true)])) 
}

pub fn tendermint_update_lc(
    context: &mut NativeContext,
    ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    todo!()
}
