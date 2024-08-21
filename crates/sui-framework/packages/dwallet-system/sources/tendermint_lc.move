#[allow(unused_function, unused_field)]
module dwallet_system::tendermint_lc {
    native fun tendermint_init_lc(): bool;
    native fun tendermint_verify_lc(): bool; 
    native fun tendermint_update_lc(): bool;
    public native fun tendermint_state_proof(proof: vector<u8>, root: vector<u8>, prefix: vector<u8>, path: vector<u8>, value: vector<u8>): bool; 
}