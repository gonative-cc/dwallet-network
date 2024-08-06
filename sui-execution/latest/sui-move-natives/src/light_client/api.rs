use ibc::{clients::tendermint::{client_state::ClientState, consensus_state::ConsensusState}, core::client::context::client_state::ClientStateExecution};

use super::context::ClientContext;

use ibc::core::client::context::consensus_state::ConsensusState as ConsensusStateTrait;


pub struct TendermintClient;

impl ClientType for TendermintClient {
    type ClientState = ClientState;
    type ConsensusState = ConsensusState;
}

pub trait ClientType: Sized {
    type ClientState: for<'a, 'b, 'c> ClientStateExecution<ClientContext<'a, 'b, 'c, Self>>;
    type ConsensusState: ConsensusStateTrait + Clone;
}
