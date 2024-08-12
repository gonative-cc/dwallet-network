#[test_only]
module dwallet_system::lc_tests {
    use dwallet_system::tendermint_lc::{tendermint_state_proof, tendermint_init_lc};
    // use std::vector;
    // use dwallet::test_scenario as ts;
    // use dwallet::object::{Self};
    // use dwallet::tx_context::TxContext;
    // use dwallet::transfer::{Self, Receiving};
    // struct ClientState has key, store {
    //     id: UID,
    //     first: u32, 
    //     second: u32
    // }

    // // ConsensusStateMap own ConsensusState 
    // // map from height => ConsensusState
    // struct ConsensusStateMap has key, store {
    //     id: UID
    // }

    // struct ConsensusState has key, store {
    //     id: UID, 
    //     value: u64
    // }
    
    #[test]
    fun tendermint_state_proof_test_lc() {
        let prefix = vector[1, 2, 3];
        let proof = vector[1, 2, 3];
        let path = vector[1, 2, 3];
        let root = vector[1, 2, 3];
        let value = vector[1, 2, 3];
        assert!(tendermint_state_proof(prefix, proof, root, path, value) == false, 0);
    }



    #[test]
    fun init_lc_test() {
   
        // let prefix = vector[1, 2, 3];
        assert!(tendermint_init_lc( @0x9876) == true, 0);
     
    }  
}