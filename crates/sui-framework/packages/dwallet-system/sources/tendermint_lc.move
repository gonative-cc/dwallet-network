#[allow(unused_function, unused_field)]
module dwallet_system::tendermint_lc {
    use dwallet::object::{UID};

    struct ConsensusState has key,store {
        id: UID,
        timestamp: u64, 
        next_validators_hash: vector<u8>, 
        commitment_root: vector<u8>
    }

    struct ClientState has key, store{
        id: UID
    }

    
    public native fun tendermint_init_lc(obj: &mut UID, cs: vector<u8>): bool;

    public native fun tendermint_state_proof(prefix: vector<u8>, proof: vector<u8>, root: vector<u8>, path: vector<u8>, value: vector<u8>): bool; 
}