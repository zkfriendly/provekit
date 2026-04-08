[[kernel]]
void transpose_matrix(
    device const Fe *input [[buffer(0)]],
    device Fe *output [[buffer(1)]],
    constant TransposeParams &params [[buffer(2)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= params.total_elements) {
        return;
    }

    uint row = gid / params.cols;
    uint col = gid - row * params.cols;
    uint dst = col * params.rows + row;
    output[dst] = input[gid];
}

[[kernel]]
void mul_field_elements(
    device const Fe *lhs [[buffer(0)]],
    device const Fe *rhs [[buffer(1)]],
    device Fe *output [[buffer(2)]],
    constant FieldMulParams &params [[buffer(3)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= params.count) {
        return;
    }

    output[gid] = mont_mul(lhs[gid], rhs[gid]);
}
