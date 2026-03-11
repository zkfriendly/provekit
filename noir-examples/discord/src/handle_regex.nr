use zkregex::utils::{
   select_subarray,
   captures::capture_substring,
   sparse_array::SparseArray,
   transitions::check_transition_with_captures
};

global TRANSITION_TABLE: SparseArray<133, Field> = SparseArray {
    keys: [0x00000000, 0x00024240, 0x00024241, 0x00034e4d, 0x00046d6c, 0x00058382, 0x00062c2b, 0x00073e3d, 0x00073e3e, 0x00073f3e, 0x00073f3f, 0x0007403f, 0x00074040, 0x00074140, 0x00074141, 0x00074241, 0x00074242, 0x00074342, 0x00074343, 0x00074443, 0x00074444, 0x00074544, 0x00074545, 0x00074645, 0x00074646, 0x00074746, 0x00074747, 0x00074f4e, 0x00074f4f, 0x0007504f, 0x00075050, 0x00075150, 0x00075151, 0x00075251, 0x00075252, 0x00075352, 0x00075353, 0x00075453, 0x00075454, 0x00075554, 0x00075555, 0x00075655, 0x00075656, 0x00075756, 0x00075757, 0x00075857, 0x00075858, 0x00075958, 0x00075959, 0x00075a59, 0x00075a5a, 0x00075b5a, 0x00075b5b, 0x00075c5b, 0x00075c5c, 0x00075d5c, 0x00075d5d, 0x00075e5d, 0x00075e5e, 0x00075f5e, 0x00075f5f, 0x0007605f, 0x00076060, 0x00076160, 0x00076161, 0x00076261, 0x00076262, 0x00076362, 0x00076363, 0x00076463, 0x00076464, 0x00076564, 0x00076565, 0x00076665, 0x00076666, 0x00076766, 0x00076767, 0x00076867, 0x00076868, 0x00076d6c, 0x00076d6d, 0x00076f6e, 0x00076f6f, 0x0007706f, 0x00077070, 0x00077170, 0x00077171, 0x00077271, 0x00077272, 0x00077372, 0x00077373, 0x00077473, 0x00077474, 0x00077574, 0x00077575, 0x00077675, 0x00077676, 0x00077776, 0x00077777, 0x00077877, 0x00077878, 0x00077978, 0x00077979, 0x00077a79, 0x00077a7a, 0x00077b7a, 0x00077b7b, 0x00077c7b, 0x00077c7c, 0x00077d7c, 0x00077d7d, 0x00077e7d, 0x00077e7e, 0x00077f7e, 0x00077f7f, 0x0007807f, 0x00078080, 0x00078180, 0x00078181, 0x00078281, 0x00078282, 0x00078382, 0x00078383, 0x00078483, 0x00078484, 0x00078584, 0x00078585, 0x00078685, 0x00078686, 0x00078786, 0x00078787, 0x00078887, 0x00078888, 0x00083c3b, 0x0009100f],
    values: [0x00000000, 0x00000000, 0x00000001, 0x00000001, 0x00000001, 0x00000001, 0x00000001, 0x00000001, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000007, 0x00000005, 0x00000001, 0x00000000],
    maximum: 0x0009100f
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
    asserted_match_length: Field
) -> Field {
    // check if the next state is an accept state
    let accept_state_reached = (next_state - 8);
    let accept_state_reached_bool = (accept_state_reached == 0) as Field;

    // check if the haystack index is the asserted match length
    // should equal 1 since haystack_index should be 1 less than asserted_match)length
    let asserted_path_traversed = (asserted_match_length - haystack_index == 1) as Field;

    (1 - (accept_state_reached_bool * asserted_path_traversed))
}

/**
 * HandleRegex matching function
 * Regex: >Hey ([A-Za-z0-9_]+),
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
    let haystack: [u8; MAX_MATCH_LEN] = select_subarray::<MAX_HAYSTACK_LEN, MAX_MATCH_LEN>(in_haystack, match_start, match_length);

    check_start_state(current_states[0]);
    for i in 0..MAX_MATCH_LEN-1 {
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
            reached_end_state
        );
        reached_end_state = reached_end_state * check_accept_state(next_states[i], i as Field, match_length as Field);
    }
    assert(reached_end_state == 0, "Did not reach a valid end state");

    // Capture Group 1
    let capture_1 = capture_substring::<MAX_MATCH_LEN, CAPTURE_1_MAX_LENGTH, 1>(
       haystack,
       capture_group_1_id,
       capture_group_1_start,
       capture_group_start_indices[0]
    );

    (capture_1)
}

