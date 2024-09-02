// module support api for link and trigger future transaction
#[allow(unused_function, unused_field, unused_variable, unused_use)]
module dwallet_system::native_dwallet {
    use std::vector;
    use dwallet::object::{UID, Self, ID};
    use dwallet::tx_context::TxContext;
    use dwallet_system::dwallet::{Self, DWalletCap, MessageApproval};
    use dwallet_system::tendermint_lc::{Client, tendermint_state_proof, get_consensus_state, commitment_root, latest_height, state_proof, client_id};
   
    use dwallet::dynamic_field as field;
    use dwallet::dynamic_object_field as ofields;
    use std::hash::sha2_256;
    
    
    const EHeightInvalid: u64 = 0;
    const EStateInvalid: u64 = 1;
    const EStateProofNoMessagesToApprove: u64 = 2;
    const EClientInvalid: u64 = 3;
    
    // Wapper object wrap DWalletCap. DWalletCap owner (user) will transfer ownership to NativeDwallet Cap
    // 
    struct NativeDwalletCap has key, store {
        id: UID,
        client_id: ID,
        dwallet_cap: DWalletCap
    }

    fun create_native_dwallet_cap(client: &Client, dwallet_cap: DWalletCap, ctx: &mut TxContext): NativeDwalletCap {
        let native_dwallet_cap = NativeDwalletCap {
            id: object::new(ctx),
            dwallet_cap,
            client_id: client_id(client)
        };

        // Question: Should we transfer dwallet_cap to create native dwallet
        native_dwallet_cap
    }


  
    public fun link_dwallet(client: &Client, dwallet_cap: DWalletCap,  height: u64,  proof: vector<u8>, prefix: vector<u8>, path: vector<u8>, value: vector<u8>, ctx: &mut TxContext): NativeDwalletCap {
        // prefix and path should be a const
        let lh = latest_height(client);
        assert!(height <= lh, EHeightInvalid);
        let valid = state_proof(client, height, proof, prefix, path, value);
        assert!(valid, EStateInvalid);
        return create_native_dwallet_cap(client, dwallet_cap, ctx)
    }

    // Hash of the bunch on message on Native.
    fun compute_hash_chain(data: vector<vector<u8>>): vector<u8> {
	let hash: vector<u8> = vector::empty();
	let i = 0;
	while (i < vector::length(&data)) {
	    let current_hash = hash;
	    vector::append(&mut current_hash, *vector::borrow(&data, i));
	    hash = sha2_256(current_hash);
	    i = i + 1;
	};
	return hash
    }



    // verify user sign `messages` data on Native network
    public fun verify_native_transaction(native_dwallet_cap: &NativeDwalletCap, client: &Client, height: u64,  proof: vector<u8>, prefix: vector<u8>, path: vector<u8>, messages: vector<vector<u8>>): vector<MessageApproval> {
	assert!(object::id(client) == native_dwallet_cap.client_id, EClientInvalid);
	
	let lh = latest_height(client);
        assert!(height <= lh, EHeightInvalid);
	
	// TODO: assume Native store hash(hash_chain(messages), dwallet_cap);
	let message_hash = compute_hash_chain(messages);

	// make it more simple
	let cap_id = object::id_to_bytes(&object::id(&native_dwallet_cap.dwallet_cap));
	
	vector::append(&mut message_hash, cap_id);
	
	let value = sha2_256(message_hash);
	let valid = state_proof(client, height, proof, prefix, path, value);
	
        assert!(valid, EStateInvalid);

	assert!(vector::length(&messages) > 0, EStateProofNoMessagesToApprove);
        dwallet::approve_messages(&native_dwallet_cap.dwallet_cap, messages)
    }
}
