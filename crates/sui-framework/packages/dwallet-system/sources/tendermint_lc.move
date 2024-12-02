#[allow(unused_function, unused_field, unused_const)]
module dwallet_system::tendermint_lc {
  
    use dwallet::object::{UID, Self, ID};
    use dwallet::tx_context::TxContext;
    use dwallet::dynamic_field as field;
    use std::option as option;
    
    const PrefixInvalid: u64 = 0;
    const PathInvalid: u64 = 1;
    const CommitmentProofInvalid: u64 = 2;
    const MerkleProofInvalid: u64 = 3; 
    const HeaderInvalid: u64 = 4;
    const TimestampInvalid: u64 = 5; 
    const NextValidatorsHashInvalid: u64 = 6; 
    const EUpdateFailed: u64 = 7;
    
    // TODO: Make Client shareobject
    struct Client has key, store {
        id: UID,
	chain_id: vector<u8>,
	trust_threashold: u256,
	trusting_period: u256,
	unbonding_period: u256,
	clock_drift: u256,
	latest_height: u64,
	proof_specs: u256,
	upgrade_path: vector<u8>,
	allow_update: u256,
	frozen_height: option::Option<u256>	
    }

    public fun init_client(height: u64, chain_id: vector<u8>, trust_threashold: u256, trusting_period: u256, clock_drift: u256, ctx: &mut TxContext): Client {
	Client {
            id: object::new(ctx),
	    // chain_id: vector[105, 98, 99, 45, 48],
	    chain_id: chain_id,
            latest_height: height,
	    trust_threashold: trust_threashold,
	    trusting_period: trusting_period,
	    unbonding_period: 0,
	    clock_drift: clock_drift,
	    proof_specs: 0,
	    upgrade_path: vector[1, 2, 3],
	    allow_update: 1,
	    frozen_height: option::some(1),
        }
    }
    
    public fun client_id(client: &Client): ID {
        object::id(client)
    }

    // struct Height has store, copy, drop{
    //     height: u64, 
    //     revision_height: u64
    // }

    struct ConsensusState has store, copy, drop {
        height: u64,
        timestamp: vector<u8>, 
        next_validators_hash: vector<u8>,
        commitment_root: vector<u8>
    }

    #[test_only]
    public fun height(cs: &ConsensusState) : u64 {
        cs.height
    }
    
    #[test_only]
    public fun timestamp(cs: &ConsensusState) : vector<u8> {
        cs.timestamp
    }

    #[test_only]
    public fun next_validators_hash(cs: &ConsensusState) : vector<u8> {
        cs.next_validators_hash
    }

    public fun commitment_root(cs: &ConsensusState) : vector<u8>{
        cs.commitment_root
    }

    public fun consensus_state(height: u64, timestamp: vector<u8>, next_validators_hash: vector<u8>, commitment_root: vector<u8>): ConsensusState {
       let consensus_state =  ConsensusState {
            timestamp, 
            next_validators_hash, 
            commitment_root,
            height
        };  
        consensus_state
    }

    public fun get_consensus_state(client: &Client, height: u64): &ConsensusState {
        field::borrow(&client.id, height)
    }

    public fun latest_height(client: &Client) : u64 {
        client.latest_height
    }


    // who can do this action?
    // this action only run one time
    public fun init_consensus_state(client: &mut Client, height: u64, timestamp: vector<u8>, next_validators_hash: vector<u8>, commitment_root: vector<u8>) {	
        let cs = consensus_state(height, timestamp, next_validators_hash, commitment_root);
        field::add(&mut client.id, height, cs);
    }

    
    public fun verify_lc(client: &Client, header: vector<u8>): bool{
        let latest_height = client.latest_height;
        // TODO: use trusted height from header.  
        let consensus_state: &ConsensusState = field::borrow(&client.id, latest_height);
        let timestamp = consensus_state.timestamp;
        let next_validators_hash = consensus_state.next_validators_hash;
        let commitment_root = consensus_state.commitment_root;
	let trusting_period = client.trusting_period;
	let chain_id = client.chain_id;
	let clock_drift = client.clock_drift;
	let trust_threadshold = client.trust_threashold;
	
        tendermint_verify_lc(chain_id, clock_drift, trust_threadshold, trusting_period, timestamp, next_validators_hash, commitment_root , header)
    }

    public fun update_lc(client: &mut Client, header: vector<u8>) {
        if (verify_lc(client, header)) {
            let consensus_state = extract_consensus_state(header);
            let height = consensus_state.height;
            if (height > client.latest_height) {
                client.latest_height = height;
            };
            field::add(&mut client.id, height, consensus_state);
        } else {
            abort EUpdateFailed
        }
    }

    public fun state_proof(client: &Client, height: u64, proof: vector<u8>, prefix: vector<u8>, path: vector<u8>, value: vector<u8>): bool {
        let cs = get_consensus_state(client, height);
        tendermint_state_proof(proof, cs.commitment_root, prefix, path, value)
    }
    public native fun extract_consensus_state(header:vector<u8>): ConsensusState;
    native fun tendermint_verify_lc(chain_id: vector<u8>, clock_drift: u256, trust_threadshold: u256, trust_period: u256, timestamp: vector<u8>, next_validators_hash: vector<u8>, commitment_root: vector<u8>, header: vector<u8>): bool; 
    public native fun tendermint_state_proof(proof: vector<u8>, root: vector<u8>, prefix: vector<u8>, path: vector<u8>, value: vector<u8>): bool; 
}
