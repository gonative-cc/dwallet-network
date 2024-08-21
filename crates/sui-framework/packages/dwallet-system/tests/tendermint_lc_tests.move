#[test_only]
module dwallet_system::lc_tests {
    use dwallet_system::tendermint_lc::tendermint_state_proof;
    
    #[test]
    fun tendermint_state_proof_test() {
        let root = vector[1];
        let prefix = vector[1];
        let path = vector[1];
        let value = vector[1];
        let proof = vector[1];
        let result = tendermint_state_proof(proof, root, prefix, path, value);
        assert!(result == true, 0);
    }
    #[test]
    fun tendermint_init_lc_test() {}
    #[test]
    fun tendermint_verify_lc_test() {}
    #[test]
    fun tendermint_update_lc_test() {}
}