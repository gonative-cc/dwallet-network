#[allow(unused_function, unused_field)]
module dwallet_system::tendermint_lc {

    use dwallet::object::{UID, Self, ID};
    use dwallet::tx_context::TxContext;
    use dwallet::transfer;
    use dwallet::dynamic_field as field;

    const EUpdateFailed: u64 = 0;

    struct Client has key, store {
        id: UID,
        height: Height
    }

    struct Height has store, copy, drop{
        height: u64, 
        revision_height: u64
    }

    struct ConsensusState has store, copy, drop {
        height: Height,
        timestamp: vector<u8>, 
        next_validators_hash: vector<u8>,
        commitment_root: vector<u8>
    }


    
    fun init(ctx: &mut TxContext) {
        let client = Client {
            id: object::new(ctx),
            latest_height: Height {
                height: 0, 
                revision_height: 0
            }
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

    public fun verify_lc(client: &Client, header: vector<u8>): bool{
        let latest_height = client.height;

        let consensus_state: &ConsensusState = field::borrow(&client.id, latest_height);
        let timestamp = consensus_state.timestamp;
        let next_validators_hash = consensus_state.next_validators_hash;
        let commitment_root = consensus_state.commitment_root;
        tendermint_verify_lc(timestamp, next_validators_hash, commitment_root , header)
    }

    public fun update_lc(client: &mut Client, header: vector<u8>) {
        if (verify_lc(client, header)) {
            let consensus_state = extract_consensus_state(header);
            let height = consensus_state.height;
            field::add(&mut client.id, height, consensus_state);
        } else {
            abort EUpdateFailed;
        }
    }
    
    native fun extract_consensus_state(header:vector<u8>): ConsensusState;
    native fun tendermint_verify_lc(timestamp: vector<u8>, next_validators_hash: vector<u8>, commitment_root: vector<u8>, header: vector<u8>): bool; 
    native fun tendermint_update_lc(): bool;
    native fun tendermint_state_proof(): bool; 
}