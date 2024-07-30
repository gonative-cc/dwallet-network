use move_binary_format::errors::PartialVMResult;
use move_core_types::gas_algebra::InternalGas;
use move_vm_runtime::native_functions::NativeContext;
use move_vm_types::{
    loaded_data::runtime_types::Type, natives::function::NativeResult, pop_arg, values::{Value, VectorRef}
};

use std::collections::VecDeque;
use smallvec::smallvec;

use ibc::{clients::tendermint::client_state::verify_membership, core::{commitment_types::{commitment::{CommitmentPrefix, CommitmentProofBytes, CommitmentRoot}, proto::ics23::{commitment_proof, CommitmentProof, HostFunctionsManager}, specs::ProofSpecs}, host::types::{identifiers::{ClientId, PortId}, path::{ClientStatePath, CommitmentPath, Path, PortPath}}}};

#[derive(Clone)]
pub struct TendermintLightClientCostParams {
    pub tendermint_state_proof_cost_base: InternalGas,
    pub tendermint_init_lc_cost_base: InternalGas,
    pub tendermint_verify_lc_cost_base: InternalGas,
    pub tendermint_update_ls_cost_base: InternalGas
}

pub fn tendermint_state_proof(
    context: &mut NativeContext,
    ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    // TODO: What is ty_args in this case???
    debug_assert!(ty_args.is_empty());
    debug_assert!(args.len() == 5);

    let prefix = pop_arg!(args, Vec<u8>);
    let proof = pop_arg!(args, Vec<u8>);
    let root = pop_arg!(args, Vec<u8>);
    let path = pop_arg!(args, Vec<u8>);
    let value = pop_arg!(args, Vec<u8>);
    
    let commitment_proof = CommitmentProofBytes::try_from(proof).unwrap();
    let root = CommitmentRoot::from_bytes(&root);
    let proof_specs = ProofSpecs::cosmos();
    let prefix = CommitmentPrefix::try_from(prefix.to_vec()).unwrap();

    let path = Path::Ports(PortPath(PortId::new("10".to_owned()).unwrap()));

    match verify_membership::<HostFunctionsManager>(&proof_specs, &prefix, &commitment_proof, &root, path, value) {
        Ok(()) => Ok(NativeResult::ok(context.gas_used(), smallvec![Value::bool(true)])),
        _ =>  Ok(NativeResult::ok(context.gas_used(), smallvec![Value::bool(false)])),
    }

}

pub fn tendermint_init_lc(
    context: &mut NativeContext,
    ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    // TODO: What is ty_args in this case???
    Ok(NativeResult::ok(context.gas_used(), smallvec![Value::bool(true)]))
}

pub fn tendermint_verify_lc(
    context: &mut NativeContext,
    ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    // TODO: What is ty_args in this case???
    Ok(NativeResult::ok(context.gas_used(), smallvec![Value::bool(true)]))
}

pub fn tendermint_update_lc(
    context: &mut NativeContext,
    ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    // TODO: What is ty_args in this case???
    Ok(NativeResult::ok(context.gas_used(), smallvec![Value::bool(true)]))
}
