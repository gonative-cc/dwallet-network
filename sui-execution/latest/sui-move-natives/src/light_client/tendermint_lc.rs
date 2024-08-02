use move_binary_format::errors::PartialVMResult;
use move_core_types::gas_algebra::InternalGas;
use move_vm_runtime::{
    native_extensions::NativeContextExtensions, native_functions::NativeContext,
};
use move_vm_types::{
    loaded_data::runtime_types::Type,
    natives::function::NativeResult,
    pop_arg,
    values::{Value, VectorRef},
};

use smallvec::smallvec;
use std::{collections::VecDeque, time::Duration};

use ibc::{
    clients::tendermint::{
        client_state::{initialise, verify_membership, ClientState},
        consensus_state,
        types::{
            AllowUpdate, ClientState as ClientStateType, ConsensusState, Header, TrustThreshold,
        },
    },
    core::{
        client::types::Height,
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
};

use crate::object_runtime::ObjectRuntime;

use super::{
    api::TendermintClient,
    context::{self, ClientContext},
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

    // TODO: provide right path
    let path = Path::Ports(PortPath(PortId::new("10".to_owned()).unwrap()));

    match verify_membership::<HostFunctionsManager>(
        &proof_specs,
        &prefix,
        &commitment_proof,
        &root,
        path,
        value,
    ) {
        Ok(()) => Ok(NativeResult::ok(
            context.gas_used(),
            smallvec![Value::bool(true)],
        )),
        _ => Ok(NativeResult::ok(
            context.gas_used(),
            smallvec![Value::bool(false)],
        )),
    }
}

/**
 * create terdermint light client.
 *
 */
pub fn tendermint_init_lc(
    context: &mut NativeContext,
    ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    let cs = pop_arg!(args, Vec<u8>);
    // TODO: What is ty_args in this case???

    let five_year = 5 * 365 * 24 * 60 * 60;
    let client = ClientStateType::new(
        ChainId::new("ibc-0").unwrap(),
        TrustThreshold::ONE_THIRD,
        Duration::new(five_year, 0),
        Duration::new(five_year + 1, 0),
        Duration::new(40, 0),
        Height::new(0, 6).expect("Never fails"),
        ProofSpecs::cosmos(),
        vec!["upgrade".to_string(), "upgradedIBCState".to_string()],
        AllowUpdate {
            after_expiry: true,
            after_misbehaviour: true,
        },
    )
    .unwrap();

    let tmp = context.extensions_mut();
    let object: &mut ObjectRuntime = tmp.get_mut();

    let mut client_context: ClientContext<TendermintClient> = ClientContext::new(object);

    let cs = client_context.convert(cs);

    let client_id = ClientId::new("stand-alone", 0).unwrap();
    initialise(&client, &mut client_context, &client_id, cs.into()).unwrap();

    let gas = context.gas_used();
    Ok(NativeResult::ok(gas, smallvec![Value::bool(true)]))
}

pub fn tendermint_verify_lc(
    context: &mut NativeContext,
    ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    // TODO: What is ty_args in this case???
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
    // TODO: What is ty_args in this case???
    Ok(NativeResult::ok(
        context.gas_used(),
        smallvec![Value::bool(true)],
    ))
}
