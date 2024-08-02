use ibc::clients::tendermint::{client_state::ClientState, consensus_state::ConsensusState};

use super::context::ClientType;

pub struct TendermintClient;

impl<'a, 'b: 'a> ClientType<'a, 'b> for TendermintClient {
    type ClientState = ClientState;
    type ConsensusState = ConsensusState;
}
