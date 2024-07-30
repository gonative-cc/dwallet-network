#[test_only]
module dwallet_system::lc_tests {
    use dwallet_system::tendermint_lc::tendermint_state_proof;
    // use std::vector;

    #[test]
    fun tendermint_state_proof_test() {
        let prefix = vector[1, 2, 3];
        let proof = vector[1, 2, 3];
        let path = vector[1, 2, 3];
        let root = vector[1, 2, 3];
        let value = vector[1, 2, 3];
        assert!(tendermint_state_proof(prefix, proof, root, path, value) == true, 0);
    }
}