use move_binary_format::errors::PartialVMResult;
use move_core_types::gas_algebra::InternalGas;
use move_vm_runtime::native_functions::NativeContext;
use move_vm_types::{
    loaded_data::runtime_types::Type, natives::function::NativeResult, values::Value,
};

use std::collections::VecDeque;


#[derive(Clone)]
pub struct TendermintLightClientCostParams {
    pub tendermint_state_proof_cost_base: InternalGas
}

pub fn tendermint_state_proof(
    _context: &mut NativeContext,
    _ty_args: Vec<Type>,
    mut _args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    todo!()
}