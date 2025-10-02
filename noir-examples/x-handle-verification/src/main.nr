
mod x_handle_regex;
mod sender_domain_regex;
use std::{collections::bounded_vec::BoundedVec, hash::pedersen_hash};
use zkemail::{dkim::RSAPubkey, headers::body_hash::get_body_hash, KEY_LIMBS_2048, Sequence, utils::pack_bytes, remove_soft_line_breaks::remove_soft_line_breaks, partial_hash::partial_sha256_var_end};
fn main(
    header: BoundedVec<u8, 960>,
    pubkey: RSAPubkey<KEY_LIMBS_2048>,
    signature: [Field; KEY_LIMBS_2048],
    prover_address: [Field; 1],
    
    dkim_header_sequence: Sequence,
    body: BoundedVec<u8, 1920>,
    body_hash_index: u32,
    partial_body_hash: [u32; 8],
    partial_body_real_length: u64,
    
    decoded_body: BoundedVec<u8, 1920>,
    
    
    
    command: [Field; 20],
    
    
    x_handle_match_start: u32,
    x_handle_match_length: u32,
    x_handle_current_states: [Field; 64],
    x_handle_next_states: [Field; 64],
    
    
    x_handle_capture_group_1_id: [Field; 64],
    
    
    x_handle_capture_group_1_start: [Field; 64],
    
    x_handle_capture_group_start_indices: [Field; 1],
    
    
    sender_domain_match_start: u32,
    sender_domain_match_length: u32,
    sender_domain_current_states: [Field; 64],
    sender_domain_next_states: [Field; 64],
    
    
    sender_domain_capture_group_1_id: [Field; 64],
    
    
    sender_domain_capture_group_1_start: [Field; 64],
    
    sender_domain_capture_group_start_indices: [Field; 1],
    
    
) -> pub (Field, Field, Field, [Field; 1] , [Field; 20], BoundedVec<u8, 64>, BoundedVec<u8, 64>) {
    // check the body and header lengths are within bounds
    assert(header.len() <= 960);
    
    assert(body.len() <= 1920);
    
    // DKIM Verification
    let header_hash: [u8; 32] = pubkey.verify_dkim_signature(header, signature);
    let header_hash: [Field; 2] = pack_bytes::<32, 16>(header_hash);
    
    // Body Hash Verification
    let signed_body_hash = get_body_hash(header, dkim_header_sequence, body_hash_index);
    let computed_body_hash: [u8; 32] = partial_sha256_var_end(partial_body_hash, body.storage(), body.len() as u64, partial_body_real_length);
    assert(
        signed_body_hash == computed_body_hash,
        "SHA256 hash computed over body does not match body hash found in DKIM-signed header",
    );
    
    assert(
        remove_soft_line_breaks(body.storage(), decoded_body.storage()),
        "Decoded body does not properly remove soft line breaks",
    );
    
    
    let pubkey_hash = pubkey.hash();
    
    
    let x_handle_capture_1 = x_handle_regex::regex_match::<1920, 64>(
        decoded_body.storage(), 
        x_handle_match_start, 
        x_handle_match_length, 
        x_handle_current_states, 
        x_handle_next_states, x_handle_capture_group_1_id, x_handle_capture_group_1_start, x_handle_capture_group_start_indices
    );
    
    
    
    
    let sender_domain_capture_1 = sender_domain_regex::regex_match::<960, 64>(
        header.storage(), 
        sender_domain_match_start, 
        sender_domain_match_length, 
        sender_domain_current_states, 
        sender_domain_next_states, sender_domain_capture_group_1_id, sender_domain_capture_group_1_start, sender_domain_capture_group_start_indices
    );
    
    
    
    (pubkey_hash, header_hash[0], header_hash[1], prover_address , command, x_handle_capture_1, sender_domain_capture_1)
}
