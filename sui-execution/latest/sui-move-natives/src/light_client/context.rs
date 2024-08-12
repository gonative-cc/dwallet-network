use std::collections::VecDeque;
use std::marker::PhantomData;

use ibc::clients::tendermint::client_state::ClientState;
use ibc::clients::tendermint::consensus_state::ConsensusState;
use ibc::core::client::context::{
    prelude::ClientStateExecution, ClientExecutionContext, ExtClientExecutionContext,
};
use ibc::core::client::context::{ClientValidationContext, ExtClientValidationContext};

use ibc::core::handler::types::error::ContextError;
use ibc::core::host::types::identifiers::ClientId;
use ibc::core::host::types::path::ClientConsensusStatePath;
use move_core_types::account_address::AccountAddress;
use move_vm_runtime::native_functions::NativeContext;
use move_vm_types::loaded_data::runtime_types::Type;
use move_vm_types::natives::function::NativeResult;
use move_vm_types::values::{GlobalValue, Value};
use sui_types::base_types::ObjectID;

use crate::dynamic_field::hash_type_and_key;
use crate::get_or_fetch_object;
use crate::object_runtime::object_store::ObjectResult;
use crate::object_runtime::ObjectRuntime;

use super::api::ClientType;

const E_KEY_DOES_NOT_EXIST: u64 = 1;
const E_FIELD_TYPE_MISMATCH: u64 = 2;
const E_BCS_SERIALIZATION_FAILURE: u64 = 3;


pub struct ClientContext<'a, 'b, 'c, T: ClientType> {
    client_object_id: AccountAddress,
    context: &'c mut NativeContext<'a, 'b>,
    _market: PhantomData<T>,
}

impl<'a, 'b, 'c, T: ClientType> ClientContext<'a, 'b, 'c, T> {
    pub fn new(client_object_id: AccountAddress, context: &'c mut NativeContext<'a, 'b>) -> Self {
        Self {
            _market: PhantomData,
            client_object_id,
            context,
        }
    }
    pub fn convert(&self, cs: Vec<u8>) -> ConsensusState {
        todo!()
    }

    pub fn sui_object(&self) -> ObjectResult<GlobalValue>{
        todo!()
    }

    pub fn client_key(&mut self, client_id: ClientId)  -> Value {
        println!("Hello");
       let ty_args: Vec<Type> = vec![Type::Vector(Box::new(Type::U8))];
       let args = VecDeque::from([Value::address(self.client_object_id), Value::vector_u8(client_id.as_bytes().to_vec())]);
    // hash_type_and_key(context, ty_args, args)
    // => 

        println!("{:?} {:?}", ty_args, args);
        let ans = hash_type_and_key(self.context, ty_args, args);

        let ans = ans.unwrap();

        let mut ans = ans.result.unwrap();
        ans.pop().unwrap()
    }

    // compute key consensus key
    pub fn consensus_key_path(&mut self, client_consensus_path: ClientConsensusStatePath) -> Value{
        todo!()
    }


}

impl<'a, 'b, 'c, T: ClientType> ClientValidationContext for ClientContext<'a, 'b, 'c, T> {
    type ClientStateRef = T::ClientState;
    type ConsensusStateRef = T::ConsensusState;

    fn client_state(
        &self,
        client_id: &ibc::core::host::types::identifiers::ClientId,
    ) -> Result<Self::ClientStateRef, ContextError> {
        let global_value_result = self.sui_object();
        let global_value = match global_value_result {
            ObjectResult::MismatchedType => {
                todo!("Return error whe Mismatched type")
            }
            ObjectResult::Loaded(gv) => gv,
        };

        // todo process error here
        if !global_value.exists().unwrap() {
            todo!("Return E_KEY_DOES_NOT_EXIST Error")
        }

        todo!()
        // Ok(())
    }

    fn consensus_state(
        &self,
        client_cons_state_path: &ibc::core::host::types::path::ClientConsensusStatePath,
    ) -> Result<Self::ConsensusStateRef, ibc::core::handler::types::error::ContextError> {
        todo!()
    }

    fn client_update_meta(
        &self,
        client_id: &ibc::core::host::types::identifiers::ClientId,
        height: &ibc::core::client::types::Height,
    ) -> Result<
        (ibc::primitives::Timestamp, ibc::core::client::types::Height),
        ibc::core::handler::types::error::ContextError,
    > {
        todo!()
    }
}

impl<'a, 'b, 'c, T: ClientType> ClientExecutionContext for ClientContext<'a, 'b, 'c, T> {
    type ClientStateMut = T::ClientState;

    // add key-value client_state_path-client_state to client_object_map. 
    // if key exist then update key value store. 
    fn store_client_state(
        &mut self,
        client_state_path: ibc::core::host::types::path::ClientStatePath,
        client_state: Self::ClientStateRef,
    ) -> Result<(), ibc::core::handler::types::error::ContextError> {
        let obj_runtime: &mut ObjectRuntime = self.context.extensions_mut().get_mut();
        // dynamic_fields::add(client_id, client_state_path, client_state);
        // can we precompute data to support it easier, oh, yes. Why not? :D 
        
        Ok(())
    }

    fn store_consensus_state(
        &mut self,
        consensus_state_path: ibc::core::host::types::path::ClientConsensusStatePath,
        consensus_state: Self::ConsensusStateRef,
    ) -> Result<(), ibc::core::handler::types::error::ContextError> {
        todo!()
    }

    fn delete_consensus_state(
        &mut self,
        consensus_state_path: ibc::core::host::types::path::ClientConsensusStatePath,
    ) -> Result<(), ibc::core::handler::types::error::ContextError> {
        todo!()
    }

    fn store_update_meta(
        &mut self,
        client_id: ibc::core::host::types::identifiers::ClientId,
        height: ibc::core::client::types::Height,
        host_timestamp: ibc::primitives::Timestamp,
        host_height: ibc::core::client::types::Height,
    ) -> Result<(), ibc::core::handler::types::error::ContextError> {
        todo!()
    }

    fn delete_update_meta(
        &mut self,
        client_id: ibc::core::host::types::identifiers::ClientId,
        height: ibc::core::client::types::Height,
    ) -> Result<(), ibc::core::handler::types::error::ContextError> {
        todo!()
    }

    fn client_state_mut(
        &self,
        client_id: &ibc::core::host::types::identifiers::ClientId,
    ) -> Result<Self::ClientStateMut, ibc::core::handler::types::error::ContextError> {
        self.client_state(client_id)
    }
}

impl<'a, 'b, 'c, T: ClientType> ExtClientValidationContext for ClientContext<'a, 'b, 'c, T> {
    fn host_timestamp(
        &self,
    ) -> Result<ibc::primitives::Timestamp, ibc::core::handler::types::error::ContextError> {
        todo!()
    }

    fn host_height(
        &self,
    ) -> Result<ibc::core::client::types::Height, ibc::core::handler::types::error::ContextError>
    {
        todo!()
    }

    fn consensus_state_heights(
        &self,
        client_id: &ibc::core::host::types::identifiers::ClientId,
    ) -> Result<Vec<ibc::core::client::types::Height>, ibc::core::handler::types::error::ContextError>
    {
        todo!()
    }

    fn next_consensus_state(
        &self,
        client_id: &ibc::core::host::types::identifiers::ClientId,
        height: &ibc::core::client::types::Height,
    ) -> Result<Option<Self::ConsensusStateRef>, ibc::core::handler::types::error::ContextError>
    {
        todo!()
    }

    fn prev_consensus_state(
        &self,
        client_id: &ibc::core::host::types::identifiers::ClientId,
        height: &ibc::core::client::types::Height,
    ) -> Result<Option<Self::ConsensusStateRef>, ibc::core::handler::types::error::ContextError>
    {
        todo!()
    }
}
