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
use std::{collections::VecDeque, str::from_utf8};

use ibc::{
    core::{
        commitment_types::{
            commitment::{CommitmentPrefix, CommitmentProofBytes, CommitmentRoot}, merkle::{apply_prefix, MerkleProof}, proto::ics23::{commitment_proof, CommitmentProof, HostFunctionsManager}, specs::ProofSpecs
        },
        host::types::{
            identifiers::{ClientId, PortId},
            path::{ClientStatePath, CommitmentPath, Path, PortPath},
        },
    },
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
    let proof = pop_arg!(args, Vector).to_vec_u8()?;
    let path = pop_arg!(args, Vector).to_vec_u8()?;
    let prefix = pop_arg!(args, Vector).to_vec_u8()?;
    let root = pop_arg!(args, Vector).to_vec_u8()?;
    let value = pop_arg!(args, Vector).to_vec_u8()?;

    let Ok(prefix) = CommitmentPrefix::try_from(prefix) else {
        return Ok(NativeResult::err(context.gas_used(), 1));
    };

    let Ok(path_str) = from_utf8(path.as_slice()) else {
        return Ok(NativeResult::err(context.gas_used(), 1));
    };

    let merkle_path = apply_prefix(&prefix, vec![path_str.to_owned()]);
    
    let Ok(proof_bytes) = CommitmentProofBytes::try_from(proof) else {
        return Ok(NativeResult::err(context.gas_used(), 1)); 
    };
    
    let Ok(merkle_proof) = MerkleProof::try_from(&proof_bytes) else {
        return Ok(NativeResult::err(context.gas_used(), 1)); 
    };

    let root = CommitmentRoot::from_bytes(&root);
    
    let verified = merkle_proof.verify_membership::<HostFunctionsManager>(&ProofSpecs::cosmos(), root.into(), merkle_path, value, 0).is_ok();

    Ok(NativeResult::ok(context.gas_used(), smallvec![Value::bool(verified)]))

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
    todo!()
}

pub fn tendermint_update_lc(
    context: &mut NativeContext,
    ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    todo!()
}
