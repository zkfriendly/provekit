#version 450

struct Fe {
    uint limbs[8];
};

struct Wide {
    uint lo;
    uint hi;
};

const uint MODULUS[8] = uint[](
    0xf0000001u,
    0x43e1f593u,
    0x79b97091u,
    0x2833e848u,
    0x8181585du,
    0xb85045b6u,
    0xe131a029u,
    0x30644e72u
);

const uint N0_INV = 0xefffffffu;

uint reverse_bits_u32(uint x) {
    x = ((x & 0x55555555u) << 1u) | ((x >> 1u) & 0x55555555u);
    x = ((x & 0x33333333u) << 2u) | ((x >> 2u) & 0x33333333u);
    x = ((x & 0x0f0f0f0fu) << 4u) | ((x >> 4u) & 0x0f0f0f0fu);
    x = ((x & 0x00ff00ffu) << 8u) | ((x >> 8u) & 0x00ff00ffu);
    return (x << 16u) | (x >> 16u);
}

uint add_u32(uint a, uint b, out uint carry) {
    uint sum = a + b;
    carry = uint(sum < a);
    return sum;
}

Wide mul32(uint a, uint b) {
    uint a0 = a & 0xffffu;
    uint a1 = a >> 16u;
    uint b0 = b & 0xffffu;
    uint b1 = b >> 16u;

    uint p00 = a0 * b0;
    uint p01 = a0 * b1;
    uint p10 = a1 * b0;
    uint p11 = a1 * b1;

    uint cross_carry;
    uint cross = add_u32(p01, p10, cross_carry);

    uint middle = (p00 >> 16u) + (cross & 0xffffu);
    Wide outv;
    outv.lo = (p00 & 0xffffu) | ((middle & 0xffffu) << 16u);
    outv.hi = p11 + (cross >> 16u) + (cross_carry << 16u) + (middle >> 16u);
    return outv;
}

Wide add_wide(Wide a, Wide b) {
    Wide outv;
    uint carry;
    outv.lo = add_u32(a.lo, b.lo, carry);
    outv.hi = a.hi + b.hi + carry;
    return outv;
}

uint add_with_carry(uint a, uint b, inout uint carry) {
    uint c0;
    uint sum = add_u32(a, b, c0);
    uint c1;
    sum = add_u32(sum, carry, c1);
    carry = c0 + c1;
    return sum;
}

uint sub_with_borrow(uint a, uint b, inout uint borrow) {
    uint diff = a - b;
    uint b0 = uint(a < b);
    uint diff2 = diff - borrow;
    uint b1 = uint(diff < borrow);
    borrow = b0 + b1;
    return diff2;
}

uint add_small(uint value, uint delta, out uint carry) {
    if (delta == 0u) {
        carry = 0u;
        return value;
    }
    if (delta == 1u) {
        return add_u32(value, 1u, carry);
    }

    uint c0;
    uint tmp = add_u32(value, 1u, c0);
    uint c1;
    tmp = add_u32(tmp, 1u, c1);
    carry = c0 + c1;
    return tmp;
}

void add_small_in_place(inout uint limbs[17], uint idx, uint delta) {
    uint carry = delta;
    for (uint i = idx; i < 17u && carry != 0u; ++i) {
        limbs[i] = add_small(limbs[i], carry, carry);
    }
}

bool geq_mod(Fe a) {
    for (int i = 7; i >= 0; --i) {
        if (a.limbs[i] > MODULUS[i]) {
            return true;
        }
        if (a.limbs[i] < MODULUS[i]) {
            return false;
        }
    }
    return true;
}

Fe sub_modulus(Fe a) {
    Fe outv;
    uint borrow = 0u;
    for (uint i = 0u; i < 8u; ++i) {
        outv.limbs[i] = sub_with_borrow(a.limbs[i], MODULUS[i], borrow);
    }
    return outv;
}

Fe add_mod(Fe a, Fe b) {
    Fe outv;
    uint carry = 0u;
    for (uint i = 0u; i < 8u; ++i) {
        outv.limbs[i] = add_with_carry(a.limbs[i], b.limbs[i], carry);
    }
    if (carry != 0u || geq_mod(outv)) {
        outv = sub_modulus(outv);
    }
    return outv;
}

Fe sub_mod(Fe a, Fe b) {
    Fe outv;
    uint borrow = 0u;
    for (uint i = 0u; i < 8u; ++i) {
        outv.limbs[i] = sub_with_borrow(a.limbs[i], b.limbs[i], borrow);
    }
    if (borrow != 0u) {
        uint carry = 0u;
        for (uint i = 0u; i < 8u; ++i) {
            outv.limbs[i] = add_with_carry(outv.limbs[i], MODULUS[i], carry);
        }
    }
    return outv;
}

Fe mont_mul(Fe a, Fe b) {
    uint t[17] = uint[17](
        0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
        0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u
    );

    for (uint i = 0u; i < 8u; ++i) {
        Wide carry = Wide(0u, 0u);
        for (uint j = 0u; j < 8u; ++j) {
            Wide prod = mul32(a.limbs[j], b.limbs[i]);
            Wide acc = add_wide(prod, carry);

            uint c0;
            t[i + j] = add_u32(t[i + j], acc.lo, c0);

            uint c1;
            carry.lo = add_u32(acc.hi, c0, c1);
            carry.hi = c1;
        }

        uint tail_carry;
        t[i + 8u] = add_u32(t[i + 8u], carry.lo, tail_carry);
        add_small_in_place(t, i + 9u, carry.hi + tail_carry);
    }

    for (uint i = 0u; i < 8u; ++i) {
        uint m = t[i] * N0_INV;
        Wide carry = Wide(0u, 0u);

        for (uint j = 0u; j < 8u; ++j) {
            Wide prod = mul32(m, MODULUS[j]);
            Wide acc = add_wide(prod, carry);

            uint c0;
            t[i + j] = add_u32(t[i + j], acc.lo, c0);

            uint c1;
            carry.lo = add_u32(acc.hi, c0, c1);
            carry.hi = c1;
        }

        uint tail_carry;
        t[i + 8u] = add_u32(t[i + 8u], carry.lo, tail_carry);
        add_small_in_place(t, i + 9u, carry.hi + tail_carry);
    }

    Fe outv;
    for (uint i = 0u; i < 8u; ++i) {
        outv.limbs[i] = t[i + 8u];
    }
    if (t[16] != 0u || geq_mod(outv)) {
        outv = sub_modulus(outv);
    }
    return outv;
}

Fe from_mont(Fe a) {
    uint t[17] = uint[17](
        a.limbs[0], a.limbs[1], a.limbs[2], a.limbs[3], a.limbs[4], a.limbs[5], a.limbs[6], a.limbs[7],
        0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u
    );

    for (uint i = 0u; i < 8u; ++i) {
        uint m = t[i] * N0_INV;
        Wide carry = Wide(0u, 0u);

        for (uint j = 0u; j < 8u; ++j) {
            Wide prod = mul32(m, MODULUS[j]);
            Wide acc = add_wide(prod, carry);

            uint c0;
            t[i + j] = add_u32(t[i + j], acc.lo, c0);

            uint c1;
            carry.lo = add_u32(acc.hi, c0, c1);
            carry.hi = c1;
        }

        uint tail_carry;
        t[i + 8u] = add_u32(t[i + 8u], carry.lo, tail_carry);
        add_small_in_place(t, i + 9u, carry.hi + tail_carry);
    }

    Fe outv;
    for (uint i = 0u; i < 8u; ++i) {
        outv.limbs[i] = t[i + 8u];
    }
    if (t[16] != 0u || geq_mod(outv)) {
        outv = sub_modulus(outv);
    }
    return outv;
}
