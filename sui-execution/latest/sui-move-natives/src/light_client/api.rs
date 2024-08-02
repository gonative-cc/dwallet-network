use ibc::clients::tendermint::{client_state::ClientState, consensus_state::ConsensusState};

use super::context::ClientType;


pub struct TendermintClient;

impl<'a> ClientType<'a> for TendermintClient {
    type ClientState = ClientState;
    type ConsensusState = ConsensusState;
}