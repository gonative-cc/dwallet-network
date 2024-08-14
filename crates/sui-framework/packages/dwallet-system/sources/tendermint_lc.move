#[allow(unused_function, unused_field)]
module dwallet_system::tendermint_lc {
    use dwallet::object::{UID, Self, ID};
    use dwallet::tx_context::TxContext;
    use dwallet::transfer;
    use dwallet::dynamic_field as field;

    struct Client has key, store {
        id: UID,
        height: Height
    }

    struct Height has store, copy, drop{
        height: u64, 
        revision_height: u64
    }

    struct ConsensusState has store {
        timestamp: u64, 
        next_validators_hash: vector<u8>,
        commitment_root: vector<u8>
    }


    
    fun init(ctx: &mut TxContext) {
        let client = Client {
            id: object::new(ctx),

        };

        transfer::share_object(client);
    }

    fun consensus_state(timestamp: u64, next_validators_hash: vector<u8>, commitment_root: vector<u8>): ConsensusState {
       let consensus_state =  ConsensusState {
            timestamp, 
            next_validators_hash, 
            commitment_root
        };  
        consensus_state
    }

    public fun init_lc(client: &mut Client, timestamp: u64, next_validators_hash: vector<u8>, commitment_root: vector<u8>) {
        let cs = consensus_state(timestamp, next_validators_hash, commitment_root);
        field::add(&mut client.id, client.height, cs);
    }

    public fun verify_lc(client: &Client, untrust_cs: ConsensusState): bool{
        let latest_height = client.height;

        let consensus_state: &ConsensusState = field::borrow(&client.id, latest_height);
        
        tendermint_verify_lc(consensus_state, untrust_cs)
    }

    native fun tendermint_init_lc(): bool;
    native fun tendermint_verify_lc(consensus_state: ConsensusState, untrust_cs: ConsensusState): bool; 
    native fun tendermint_update_lc(): bool;
    native fun tendermint_state_proof(): bool; 
}