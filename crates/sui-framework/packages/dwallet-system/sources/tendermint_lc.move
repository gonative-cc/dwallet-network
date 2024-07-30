#[allow(unused_function)]
module dwallet_system::tendermint_lc {
    public native fun tendermint_state_proof(prefix: vector<u8>, proof: vector<u8>, root: vector<u8>, path: vector<u8>, value: vector<u8>): bool; 
}