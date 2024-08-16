#[test_only]
module dwallet_system::lc_tests {

    const SENDER: address = @0x012;

    use dwallet::test_scenario;
    // use dwallet::dynamic_field as fields;
    use dwallet::test_utils::{Self};
    use dwallet_system::tendermint_lc::{init_lc, Self};
    
    #[test]
    fun tendermint_state_proof_test() {}
    #[test]
    fun tendermint_init_lc_test() {
        let scenario = test_scenario::begin(SENDER);
        let height = tendermint_lc::create_height(3, 0);

        let timestamp: vector<u8> = vector[1];
        let next_validators_hash : vector<u8> = vector[2];
        let root: vector<u8> = vector[3];
        let ctx = test_scenario::ctx(&mut scenario);
        let client = init_lc(height, timestamp, next_validators_hash, root, ctx);
        
        assert!(tendermint_lc::latest_height(&client) == height, 0);
        test_scenario::end(scenario);
        test_utils::destroy(client);
    }
    #[test]
    fun tendermint_verify_lc_test() {}
    #[test]
    fun tendermint_update_lc_test() {}
}