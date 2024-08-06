use std::marker::PhantomData;

use ibc::clients::tendermint::client_state::ClientState;
use ibc::clients::tendermint::consensus_state::ConsensusState;
use ibc::core::client::context::{
    prelude::ClientStateExecution, ClientExecutionContext, ExtClientExecutionContext,
};
use ibc::core::client::context::{ClientValidationContext, ExtClientValidationContext};

use move_vm_runtime::native_functions::NativeContext;

use super::api::ClientType;



pub struct ClientContext<'a, 'b, 'c, T: ClientType> {
    object_runtime: &'c mut NativeContext<'a, 'b>,
    _market: PhantomData<T>,
}

impl<'a, 'b, 'c, T: ClientType> ClientContext<'a, 'b, 'c, T> {
    pub fn new(object_runtime: &'c mut NativeContext<'a, 'b>) -> Self {
        Self {
            _market: PhantomData,
            object_runtime,
        }
    }
    pub fn convert(&self, cs: Vec<u8>) -> ConsensusState {
        todo!()
    }
}

impl<'a, 'b, 'c, T: ClientType> ClientValidationContext for ClientContext<'a, 'b, 'c, T> {
    type ClientStateRef = T::ClientState;
    type ConsensusStateRef = T::ConsensusState;

    fn client_state(
        &self,
        client_id: &ibc::core::host::types::identifiers::ClientId,
    ) -> Result<Self::ClientStateRef, ibc::core::handler::types::error::ContextError> {
        todo!()
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

    fn store_client_state(
        &mut self,
        client_state_path: ibc::core::host::types::path::ClientStatePath,
        client_state: Self::ClientStateRef,
    ) -> Result<(), ibc::core::handler::types::error::ContextError> {
        todo!()
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
