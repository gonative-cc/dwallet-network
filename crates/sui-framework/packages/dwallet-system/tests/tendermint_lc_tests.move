#[test_only]
module dwallet_system::lc_tests {
    use dwallet_system::tendermint_lc::tendermint_state_proof;

    #[test]
    fun tendermint_state_proof_test() {
        assert!(tendermint_state_proof() == 42, 0);
    }
}