struct HashManyParams {
  size: u32,
  count: u32,
  input_offset_words: u32,
  output_offset_words: u32,
}

@group(0) @binding(0)
var<storage, read> input_words: array<u32>;

@group(0) @binding(1)
var<storage, read_write> output_words: array<u32>;

@group(0) @binding(2)
var<storage, read> params: HashManyParams;

const SHA256_K: array<u32, 64> = array<u32, 64>(
  0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
  0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
  0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
  0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
  0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
  0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
  0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
  0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
  0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
  0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
  0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
  0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
  0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
  0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
  0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
  0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
);

fn rotr32(x: u32, n: u32) -> u32 {
  return (x >> n) | (x << (32u - n));
}

fn ch(x: u32, y: u32, z: u32) -> u32 {
  return (x & y) ^ ((~x) & z);
}

fn maj(x: u32, y: u32, z: u32) -> u32 {
  return (x & y) ^ (x & z) ^ (y & z);
}

fn big_sigma0(x: u32) -> u32 {
  return rotr32(x, 2u) ^ rotr32(x, 13u) ^ rotr32(x, 22u);
}

fn big_sigma1(x: u32) -> u32 {
  return rotr32(x, 6u) ^ rotr32(x, 11u) ^ rotr32(x, 25u);
}

fn small_sigma0(x: u32) -> u32 {
  return rotr32(x, 7u) ^ rotr32(x, 18u) ^ (x >> 3u);
}

fn small_sigma1(x: u32) -> u32 {
  return rotr32(x, 17u) ^ rotr32(x, 19u) ^ (x >> 10u);
}

fn load_input_byte(base_word: u32, byte_index: u32) -> u32 {
  let word = input_words[base_word + (byte_index >> 2u)];
  let shift = (byte_index & 3u) * 8u;
  return (word >> shift) & 0xffu;
}

fn store_digest_word(x: u32) -> u32 {
  return ((x & 0x000000ffu) << 24u)
    | ((x & 0x0000ff00u) << 8u)
    | ((x & 0x00ff0000u) >> 8u)
    | ((x & 0xff000000u) >> 24u);
}

@compute @workgroup_size(128)
fn main(@builtin(global_invocation_id) global_id: vec3<u32>) {
  let gid = global_id.x;
  if (gid >= params.count) {
    return;
  }

  let offset_words = params.input_offset_words + gid * (params.size >> 2u);
  let total_blocks = (params.size + 9u + 63u) / 64u;
  let total_padded_len = total_blocks * 64u;
  let bit_len_lo = params.size << 3u;
  let bit_len_hi = params.size >> 29u;

  var h0 = 0x6a09e667u;
  var h1 = 0xbb67ae85u;
  var h2 = 0x3c6ef372u;
  var h3 = 0xa54ff53au;
  var h4 = 0x510e527fu;
  var h5 = 0x9b05688cu;
  var h6 = 0x1f83d9abu;
  var h7 = 0x5be0cd19u;

  for (var block = 0u; block < total_blocks; block += 1u) {
    var w: array<u32, 64>;

    for (var i = 0u; i < 16u; i += 1u) {
      var word = 0u;
      for (var j = 0u; j < 4u; j += 1u) {
        let idx = block * 64u + i * 4u + j;
        var byte = 0u;
        if (idx < params.size) {
          byte = load_input_byte(offset_words, idx);
        } else if (idx == params.size) {
          byte = 0x80u;
        } else if (idx >= total_padded_len - 8u) {
          let shift = (total_padded_len - 1u - idx) * 8u;
          if (shift >= 32u) {
            byte = (bit_len_hi >> (shift - 32u)) & 0xffu;
          } else {
            byte = (bit_len_lo >> shift) & 0xffu;
          }
        }
        word = (word << 8u) | byte;
      }
      w[i] = word;
    }

    for (var i = 16u; i < 64u; i += 1u) {
      w[i] = small_sigma1(w[i - 2u]) + w[i - 7u] + small_sigma0(w[i - 15u]) + w[i - 16u];
    }

    var a = h0;
    var b = h1;
    var c = h2;
    var d = h3;
    var e = h4;
    var f = h5;
    var g = h6;
    var h = h7;

    for (var i = 0u; i < 64u; i += 1u) {
      let t1 = h + big_sigma1(e) + ch(e, f, g) + SHA256_K[i] + w[i];
      let t2 = big_sigma0(a) + maj(a, b, c);
      h = g;
      g = f;
      f = e;
      e = d + t1;
      d = c;
      c = b;
      b = a;
      a = t1 + t2;
    }

    h0 = h0 + a;
    h1 = h1 + b;
    h2 = h2 + c;
    h3 = h3 + d;
    h4 = h4 + e;
    h5 = h5 + f;
    h6 = h6 + g;
    h7 = h7 + h;
  }

  let out_base = params.output_offset_words + gid * 8u;
  output_words[out_base + 0u] = store_digest_word(h0);
  output_words[out_base + 1u] = store_digest_word(h1);
  output_words[out_base + 2u] = store_digest_word(h2);
  output_words[out_base + 3u] = store_digest_word(h3);
  output_words[out_base + 4u] = store_digest_word(h4);
  output_words[out_base + 5u] = store_digest_word(h5);
  output_words[out_base + 6u] = store_digest_word(h6);
  output_words[out_base + 7u] = store_digest_word(h7);
}
