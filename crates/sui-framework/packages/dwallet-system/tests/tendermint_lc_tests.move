#[test_only]
module dwallet_system::lc_tests {
    use dwallet_system::tendermint_lc::{tendermint_state_proof, tendermint_init_lc};
    // use std::vector;
      use dwallet::test_scenario as ts;
use dwallet::object;
    #[test]
    fun tendermint_state_proof_test() {
        let prefix = vector[1, 2, 3];
        let proof = vector[1, 2, 3];
        let path = vector[1, 2, 3];
        let root = vector[1, 2, 3];
        let value = vector[1, 2, 3];
        assert!(tendermint_state_proof(prefix, proof, root, path, value) == false, 0);
    }


    #[test]
    fun init_client_test() {
        let sender = @0x0;
        let scenario = ts::begin(sender);
        let id = ts::new_object(&mut scenario);

        let prefix = vector[1, 2, 3];
        // let proof = vector[1, 2, 3];
        // let path = vector[1, 2, 3];
        // let root = vector[1, 2, 3];
        // let value = vector[1, 2, 3];
        
        assert!(tendermint_init_lc(&mut id, prefix) == false, 0);
        ts::end(scenario);
        object::delete(id);
    }  
}