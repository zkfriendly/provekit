use zkregex::utils::{
    captures::capture_substring, select_subarray, sparse_array::SparseArray,
    transitions::check_transition_with_captures,
};

global TRANSITION_TABLE: SparseArray<161, Field> = SparseArray {
    keys: [
        0x00000000, 0x00025856, 0x00025857, 0x00036e6d, 0x00047170, 0x00057d7c, 0x00062c2b,
        0x00077372, 0x00087d7c, 0x00097372, 0x000a7d7c, 0x000b8281, 0x000c3837, 0x000d9190,
        0x000e7d7c, 0x000f9190, 0x0010403f, 0x00118f8e, 0x00128988, 0x00138786, 0x00149695,
        0x00159e9d, 0x00164c4b, 0x00179493, 0x00189f9e, 0x0019a4a3, 0x001a5453, 0x001b7675,
        0x001c6867, 0x001c6868, 0x001c6968, 0x001c6969, 0x001c6a69, 0x001c6a6a, 0x001c6b6a,
        0x001c6b6b, 0x001c6c6b, 0x001c6c6c, 0x001c6d6c, 0x001c6d6d, 0x001c6e6d, 0x001c6e6e,
        0x001c6f6e, 0x001c6f6f, 0x001c706f, 0x001c7070, 0x001c7170, 0x001c7171, 0x001c7978,
        0x001c7979, 0x001c7a79, 0x001c7a7a, 0x001c7b7a, 0x001c7b7b, 0x001c7c7b, 0x001c7c7c,
        0x001c7d7c, 0x001c7d7d, 0x001c7e7d, 0x001c7e7e, 0x001c7f7e, 0x001c7f7f, 0x001c807f,
        0x001c8080, 0x001c8180, 0x001c8181, 0x001c8281, 0x001c8282, 0x001c8382, 0x001c8383,
        0x001c8483, 0x001c8484, 0x001c8584, 0x001c8585, 0x001c8685, 0x001c8686, 0x001c8786,
        0x001c8787, 0x001c8887, 0x001c8888, 0x001c8988, 0x001c8989, 0x001c8a89, 0x001c8a8a,
        0x001c8b8a, 0x001c8b8b, 0x001c8c8b, 0x001c8c8c, 0x001c8d8c, 0x001c8d8d, 0x001c8e8d,
        0x001c8e8e, 0x001c8f8e, 0x001c8f8f, 0x001c908f, 0x001c9090, 0x001c9190, 0x001c9191,
        0x001c9291, 0x001c9292, 0x001c9796, 0x001c9797, 0x001c9998, 0x001c9999, 0x001c9a99,
        0x001c9a9a, 0x001c9b9a, 0x001c9b9b, 0x001c9c9b, 0x001c9c9c, 0x001c9d9c, 0x001c9d9d,
        0x001c9e9d, 0x001c9e9e, 0x001c9f9e, 0x001c9f9f, 0x001ca09f, 0x001ca0a0, 0x001ca1a0,
        0x001ca1a1, 0x001ca2a1, 0x001ca2a2, 0x001ca3a2, 0x001ca3a3, 0x001ca4a3, 0x001ca4a4,
        0x001ca5a4, 0x001ca5a5, 0x001ca6a5, 0x001ca6a6, 0x001ca7a6, 0x001ca7a7, 0x001ca8a7,
        0x001ca8a8, 0x001ca9a8, 0x001ca9a9, 0x001caaa9, 0x001caaaa, 0x001cabaa, 0x001cabab,
        0x001cacab, 0x001cacac, 0x001cadac, 0x001cadad, 0x001caead, 0x001caeae, 0x001cafae,
        0x001cafaf, 0x001cb0af, 0x001cb0b0, 0x001cb1b0, 0x001cb1b1, 0x001cb2b1, 0x001cb2b2,
        0x001d5a59, 0x001e7877, 0x001f6d6c, 0x0020b3b2, 0x0021b2b1, 0x0022a5a4, 0x0023b4b3,
        0x00248685, 0x00254847,
    ],
    values: [
        0x00000000, 0x00000000, 0x00000001, 0x00000001, 0x00000001, 0x00000001, 0x00000001,
        0x00000001, 0x00000001, 0x00000001, 0x00000001, 0x00000001, 0x00000001, 0x00000001,
        0x00000001, 0x00000001, 0x00000001, 0x00000001, 0x00000001, 0x00000001, 0x00000001,
        0x00000001, 0x00000001, 0x00000001, 0x00000001, 0x00000001, 0x00000001, 0x00000001,
        0x00000001, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005,
        0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007,
        0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005,
        0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007,
        0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005,
        0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007,
        0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005,
        0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007,
        0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005,
        0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007,
        0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005,
        0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007,
        0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005,
        0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007,
        0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005,
        0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007,
        0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005,
        0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007,
        0x00000005, 0x00000001, 0x00000001, 0x00000001, 0x00000001, 0x00000001, 0x00000001,
        0x00000001, 0x00000001, 0x00000000,
    ],
    maximum: 0x00254847,
};

pub global CAPTURE_1_MAX_LENGTH: u32 = 64;
pub global NUM_CAPTURE_GROUPS: u32 = 1;

/**
 * Constrains a start state to be valid
 * @dev start states are hardcoded in this function - "(start_state - {state})" for each start
 *      example: `(start_state - 0) * (start_state - 1) * (start_state - 2)` means 0, 1, or 2
 *      are valid first states
 * 
 * @param start_state - The start state of the NFA
 */
fn check_start_state(start_state: Field) {
    let valid_start_state = (start_state - 0) * (start_state - 1);
    assert(valid_start_state == 0, "Invalid start state");
}

/**
 * Constrains the recognition of accept_state being reached. If an aceppt state is reached,
 *      ensures asserted traversal path is valid
 * @dev accept states are hardcoded in this function - "(next_state - {state})" for each accept
 *      example: `(next_state - 19) * (next_state - 20) * (next_state - 21)` means 19, 20, or 21
 *      are valid accept states
 * 
 * @param next_state - The asserted next state of the NFA
 * @param haystack_index - The index being operated on in the haystack
 * @param asserted_match_length - The asserted traversal path length
 * @return - 0 if accept_state is reached, nonzero otherwise
 */
fn check_accept_state(
    next_state: Field,
    haystack_index: Field,
    asserted_match_length: Field,
) -> Field {
    // check if the next state is an accept state
    let accept_state_reached = (next_state - 36);
    let accept_state_reached_bool = (accept_state_reached == 0) as Field;

    // check if the haystack index is the asserted match length
    // should equal 1 since haystack_index should be 1 less than asserted_match)length
    let asserted_path_traversed = (asserted_match_length - haystack_index == 1) as Field;

    (1 - (accept_state_reached_bool * asserted_path_traversed))
}

/**
 * XHandleRegex matching function
 * Regex: This email was meant for @([A-Za-z0-9_]+) </span>
 * @param in_haystack - The input haystack to search from
 * @param match_start - The start index in the haystack for the subarray to match from
 * @param match_length - The length of the subarray to extract from haystack
 * @param current_states - The current states of the NFA at each index in the match subarray
 * @param next_states - The next states of the NFA at each index in the match subarray
 * @param capture_group_<group>_ids - The ids of the capture groups in the match subarray
 * @param capture_group_<group>_starts - The start positions of the capture groups in the match subarray
 * @param capture_group_start_indices - The start indices of the capture groups in the match subarray
 * @return - tuple of substring captures as dictated by the regular expression
 */
pub fn regex_match<let MAX_HAYSTACK_LEN: u32, let MAX_MATCH_LEN: u32>(
    in_haystack: [u8; MAX_HAYSTACK_LEN],
    match_start: u32,
    match_length: u32,
    current_states: [Field; MAX_MATCH_LEN],
    next_states: [Field; MAX_MATCH_LEN],
    capture_group_1_id: [Field; MAX_MATCH_LEN],
    capture_group_1_start: [Field; MAX_MATCH_LEN],
    capture_group_start_indices: [Field; NUM_CAPTURE_GROUPS],
) -> (BoundedVec<u8, CAPTURE_1_MAX_LENGTH>) {
    // resize haystack
    let haystack: [u8; MAX_MATCH_LEN] =
        select_subarray::<MAX_HAYSTACK_LEN, MAX_MATCH_LEN>(in_haystack, match_start, match_length);

    check_start_state(current_states[0]);
    for i in 0..MAX_MATCH_LEN - 1 {
        // match length - 1 since current states should be 1 less than next states
        let in_range = (i < match_length - 1) as Field;
        let matching_states = current_states[i + 1] - next_states[i];
        assert(in_range * matching_states == 0, "Invalid Transition Input");
    }
    let mut reached_end_state = 1;
    for i in 0..MAX_MATCH_LEN {
        let active_capture_groups_at_index = [capture_group_1_id[i]];
        let active_capture_groups_starts_at_index = [capture_group_1_start[i]];
        check_transition_with_captures(
            TRANSITION_TABLE,
            haystack[i] as Field,
            current_states[i],
            next_states[i],
            active_capture_groups_at_index,
            active_capture_groups_starts_at_index,
            reached_end_state,
        );
        reached_end_state = reached_end_state
            * check_accept_state(next_states[i], i as Field, match_length as Field);
    }
    assert(reached_end_state == 0, "Did not reach a valid end state");

    // Capture Group 1
    let capture_1 = capture_substring::<MAX_MATCH_LEN, CAPTURE_1_MAX_LENGTH, 1>(
        haystack,
        capture_group_1_id,
        capture_group_1_start,
        capture_group_start_indices[0],
    );

    (capture_1)
}
