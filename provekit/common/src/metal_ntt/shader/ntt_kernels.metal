[[kernel]]
void bit_reverse_permute_in_place(
    device Fe *values [[buffer(0)]],
    constant BitReverseConfig &config [[buffer(1)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= config.total_elements) {
        return;
    }

    uint row_len = config.row_len;
    uint row = gid / row_len;
    uint index = gid - row * row_len;
    uint reversed = reverse_low_bits(index, config.log_n);
    if (reversed <= index) {
        return;
    }

    uint row_base = row * row_len;
    Fe tmp = values[row_base + index];
    values[row_base + index] = values[row_base + reversed];
    values[row_base + reversed] = tmp;
}

[[kernel]]
void radix2_ntt_stage(
    device Fe *values [[buffer(0)]],
    device const Fe *twiddles [[buffer(1)]],
    constant StageConfig &config [[buffer(2)]],
    uint gid [[thread_position_in_grid]]
) {
    uint butterflies_per_row = config.row_len >> 1u;
    uint row = gid / butterflies_per_row;
    uint local = gid - row * butterflies_per_row;
    uint pair_in_group = local % config.half_m;
    uint group = local / config.half_m;

    uint row_base = row * config.row_len;
    uint base = row_base + group * (config.half_m << 1u) + pair_in_group;
    uint mate = base + config.half_m;

    Fe even = values[base];
    Fe odd = values[mate];
    Fe twiddle = twiddles[config.twiddle_offset + pair_in_group];
    Fe t = mont_mul(twiddle, odd);

    values[base] = add_mod(even, t);
    values[mate] = sub_mod(even, t);
}
