use std::{
    env,
    ffi::c_void,
    mem::size_of,
    sync::{Arc, OnceLock},
    time::Instant,
};

use metal::{
    objc::rc::autoreleasepool, Buffer, CommandQueue, CompileOptions, ComputePipelineState, Device,
    MTLResourceOptions, MTLSize, NSUInteger,
};
use sha2::digest::const_oid::{AssociatedOid, ObjectIdentifier};
use tracing::info;
use whir::hash::{Hash, HashEngine, Sha2};

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct HashManyParams {
    size:  u64,
    count: u64,
}

struct MetalSha2Runtime {
    device:   Device,
    queue:    CommandQueue,
    pipeline: ComputePipelineState,
}

static RUNTIME: OnceLock<Result<Arc<MetalSha2Runtime>, String>> = OnceLock::new();
static PREFERRED_BATCH_SIZE: OnceLock<usize> = OnceLock::new();

#[derive(Clone, Copy, Debug, Default)]
pub struct MetalSha2HashEngine;

impl MetalSha2HashEngine {
    pub fn new() -> Result<Self, String> {
        if env::var_os("PROVEKIT_DISABLE_METAL_SHA2").is_some() {
            return Err("Metal SHA2 disabled via PROVEKIT_DISABLE_METAL_SHA2".into());
        }

        match RUNTIME.get_or_init(|| MetalSha2Runtime::new().map(Arc::new)) {
            Ok(runtime) => {
                info!(
                    device = runtime.device.name(),
                    preferred_batch_size = preferred_batch_size(),
                    thread_execution_width = runtime.pipeline.thread_execution_width(),
                    max_total_threads_per_threadgroup = runtime
                        .pipeline
                        .max_total_threads_per_threadgroup(),
                    "initialized Metal SHA2 backend"
                );
                trace_event(format_args!(
                    "init device={} preferred_batch_size={} thread_execution_width={} max_total_threads_per_threadgroup={}",
                    runtime.device.name(),
                    preferred_batch_size(),
                    runtime.pipeline.thread_execution_width(),
                    runtime.pipeline.max_total_threads_per_threadgroup()
                ));
                Ok(Self)
            }
            Err(err) => Err(err.clone()),
        }
    }

    fn runtime(&self) -> Result<&Arc<MetalSha2Runtime>, String> {
        match RUNTIME.get() {
            Some(Ok(runtime)) => Ok(runtime),
            Some(Err(err)) => Err(err.clone()),
            None => Err("metal sha2 runtime not initialized".into()),
        }
    }

    fn gpu_hash_many(&self, size: usize, input: &[u8], output: &mut [Hash]) -> Result<(), String> {
        let total_started = Instant::now();
        let runtime = self.runtime()?;
        let count = output.len();

        if count == 0 {
            return Ok(());
        }
        if size == 0 {
            let cpu = Sha2::new();
            cpu.hash_many(size, input, output);
            return Ok(());
        }
        if input.len() != size * count {
            return Err(format!(
                "input length {} != size {} * count {}",
                input.len(),
                size,
                count
            ));
        }
        if count > u32::MAX as usize {
            return Err("GPU SHA2 launch exceeds current 32-bit grid limit".into());
        }

        let encode_started = Instant::now();
        let input = runtime.buffer_with_data(input);
        let output_buffer = runtime.empty_buffer::<u8>(count * size_of::<Hash>());
        let encode_elapsed = encode_started.elapsed();

        let params = HashManyParams {
            size:  size as u64,
            count: count as u64,
        };
        let gpu_started = Instant::now();
        let command_buffer = runtime.queue.new_command_buffer();
        let encoder = command_buffer.new_compute_command_encoder();
        encoder.set_compute_pipeline_state(&runtime.pipeline);
        encoder.set_buffer(0, Some(&input), 0);
        encoder.set_buffer(1, Some(&output_buffer), 0);
        encoder.set_bytes(
            2,
            size_of::<HashManyParams>() as NSUInteger,
            (&params as *const HashManyParams).cast::<c_void>(),
        );
        let threads = runtime.threads_per_threadgroup(count);
        encoder.dispatch_threads(
            MTLSize {
                width: count as u64,
                height: 1,
                depth: 1,
            },
            threads,
        );
        encoder.end_encoding();
        command_buffer.commit();
        command_buffer.wait_until_completed();
        let gpu_elapsed = gpu_started.elapsed();

        let readback_started = Instant::now();
        runtime.read_bytes_into_hashes(&output_buffer, output);
        let readback_elapsed = readback_started.elapsed();
        trace_event(format_args!(
            "hash_many size={} count={} encode_us={} gpu_us={} readback_us={} total_us={}",
            size,
            count,
            encode_elapsed.as_micros(),
            gpu_elapsed.as_micros(),
            readback_elapsed.as_micros(),
            total_started.elapsed().as_micros()
        ));
        Ok(())
    }
}

impl HashEngine for MetalSha2HashEngine {
    fn name(&self) -> std::borrow::Cow<'_, str> {
        "metal-sha2".into()
    }

    fn oid(&self) -> Option<ObjectIdentifier> {
        Some(sha2::Sha256::OID)
    }

    fn supports_size(&self, _size: usize) -> bool {
        true
    }

    fn preferred_batch_size(&self) -> usize {
        preferred_batch_size()
    }

    fn hash_many(&self, size: usize, input: &[u8], output: &mut [Hash]) {
        self.gpu_hash_many(size, input, output).unwrap_or_else(|err| {
            panic!(
                "Metal SHA2 execution failed for size={} count={}: {}",
                size,
                output.len(),
                err
            )
        });
    }
}

impl MetalSha2Runtime {
    fn new() -> Result<Self, String> {
        autoreleasepool(|| {
            let device = Device::system_default()
                .or_else(|| Device::all().into_iter().next())
                .ok_or_else(|| {
                    "no Metal device found; sandboxed macOS processes may not expose Metal"
                        .to_string()
                })?;
            let options = CompileOptions::new();
            let library = device.new_library_with_source(SHADER_SOURCE, &options)?;
            let pipeline = library
                .get_function("sha256_many", None)
                .map_err(|err| err.to_string())
                .and_then(|function| device.new_compute_pipeline_state_with_function(&function))?;
            let queue = device.new_command_queue();

            Ok(Self {
                device,
                queue,
                pipeline,
            })
        })
    }

    fn buffer_with_data<T: Copy>(&self, values: &[T]) -> Buffer {
        self.device.new_buffer_with_data(
            values.as_ptr().cast::<c_void>(),
            std::mem::size_of_val(values) as NSUInteger,
            MTLResourceOptions::StorageModeShared,
        )
    }

    fn empty_buffer<T>(&self, len: usize) -> Buffer {
        self.device.new_buffer(
            (len * size_of::<T>()) as u64,
            MTLResourceOptions::StorageModeShared,
        )
    }

    fn read_bytes_into_hashes(&self, buffer: &Buffer, output: &mut [Hash]) {
        let ptr = buffer.contents().cast::<u8>();
        let bytes =
            unsafe { std::slice::from_raw_parts(ptr, output.len() * size_of::<Hash>()) };
        let out_bytes = unsafe {
            std::slice::from_raw_parts_mut(
                output.as_mut_ptr().cast::<u8>(),
                output.len() * size_of::<Hash>(),
            )
        };
        out_bytes.copy_from_slice(bytes);
    }

    fn threads_per_threadgroup(&self, work_items: usize) -> MTLSize {
        let width = self
            .pipeline
            .thread_execution_width()
            .min(self.pipeline.max_total_threads_per_threadgroup())
            .min(work_items as u64)
            .max(1);
        MTLSize {
            width,
            height: 1,
            depth: 1,
        }
    }
}

fn trace_event(args: std::fmt::Arguments<'_>) {
    if env::var_os("PROVEKIT_METAL_SHA2_TRACE").is_some() {
        eprintln!("[provekit-metal-sha2] {args}");
    }
}

fn preferred_batch_size() -> usize {
    *PREFERRED_BATCH_SIZE.get_or_init(|| {
        env::var("PROVEKIT_METAL_SHA2_PREFERRED_BATCH_SIZE")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|&value| value > 0)
            .unwrap_or(256)
    })
}

const SHADER_SOURCE: &str = r#"
#include <metal_stdlib>
using namespace metal;

struct HashManyParams {
    ulong size;
    ulong count;
};

constant uint K[64] = {
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
};

inline uint rotr32(uint x, uint n) {
    return (x >> n) | (x << (32 - n));
}

inline uint ch(uint x, uint y, uint z) {
    return (x & y) ^ ((~x) & z);
}

inline uint maj(uint x, uint y, uint z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

inline uint big_sigma0(uint x) {
    return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22);
}

inline uint big_sigma1(uint x) {
    return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25);
}

inline uint small_sigma0(uint x) {
    return rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3);
}

inline uint small_sigma1(uint x) {
    return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10);
}

kernel void sha256_many(
    device const uchar* input [[buffer(0)]],
    device uchar* output [[buffer(1)]],
    constant HashManyParams& params [[buffer(2)]],
    uint gid [[thread_position_in_grid]]
) {
    if ((ulong)gid >= params.count) {
        return;
    }

    ulong offset = (ulong)gid * params.size;
    ulong total_blocks = (params.size + 9ul + 63ul) / 64ul;
    ulong total_padded_len = total_blocks * 64ul;
    ulong bit_len = params.size * 8ul;

    uint h0 = 0x6a09e667u;
    uint h1 = 0xbb67ae85u;
    uint h2 = 0x3c6ef372u;
    uint h3 = 0xa54ff53au;
    uint h4 = 0x510e527fu;
    uint h5 = 0x9b05688cu;
    uint h6 = 0x1f83d9abu;
    uint h7 = 0x5be0cd19u;

    for (ulong block = 0; block < total_blocks; ++block) {
        uint w[64];

        for (uint i = 0; i < 16; ++i) {
            uint word = 0u;
            for (uint j = 0; j < 4; ++j) {
                ulong idx = block * 64ul + (ulong)i * 4ul + (ulong)j;
                uchar byte = 0u;
                if (idx < params.size) {
                    byte = input[offset + idx];
                } else if (idx == params.size) {
                    byte = 0x80u;
                } else if (idx >= total_padded_len - 8ul) {
                    uint shift = (uint)((total_padded_len - 1ul - idx) * 8ul);
                    byte = uchar((bit_len >> shift) & 0xfful);
                }
                word = (word << 8) | uint(byte);
            }
            w[i] = word;
        }

        for (uint i = 16; i < 64; ++i) {
            w[i] = small_sigma1(w[i - 2]) + w[i - 7] + small_sigma0(w[i - 15]) + w[i - 16];
        }

        uint a = h0;
        uint b = h1;
        uint c = h2;
        uint d = h3;
        uint e = h4;
        uint f = h5;
        uint g = h6;
        uint h = h7;

        for (uint i = 0; i < 64; ++i) {
            uint t1 = h + big_sigma1(e) + ch(e, f, g) + K[i] + w[i];
            uint t2 = big_sigma0(a) + maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
        h5 += f;
        h6 += g;
        h7 += h;
    }

    device uchar* out = output + (ulong)gid * 32ul;
    uint digest[8] = {h0, h1, h2, h3, h4, h5, h6, h7};
    for (uint i = 0; i < 8; ++i) {
        out[i * 4 + 0] = uchar((digest[i] >> 24) & 0xffu);
        out[i * 4 + 1] = uchar((digest[i] >> 16) & 0xffu);
        out[i * 4 + 2] = uchar((digest[i] >> 8) & 0xffu);
        out[i * 4 + 3] = uchar(digest[i] & 0xffu);
    }
}
"#;

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::MetalSha2HashEngine;
    use ark_bn254::Fr;
    use ark_ff::UniformRand;
    use whir::{
        engines::Engine as _,
        hash::{Hash, HashEngine, Sha2, SHA2},
        protocols::matrix_commit,
        transcript::{codecs::Empty, DomainSeparator, ProverState, VerifierState},
    };
    use zerocopy::IntoBytes;

    fn random_messages(size: usize, count: usize) -> Vec<u8> {
        let mut rng = ark_std::test_rng();
        let mut input = vec![0u8; size * count];
        use ark_std::rand::RngCore;
        rng.fill_bytes(&mut input);
        input
    }

    fn merkle_root(engine: &dyn HashEngine, num_leaves: usize, leaves: &[Hash]) -> Hash {
        if num_leaves == 0 {
            return Hash::default();
        }

        let padded = num_leaves.next_power_of_two();
        let mut layer = vec![Hash::default(); padded];
        layer[..num_leaves].copy_from_slice(&leaves[..num_leaves]);
        while layer.len() > 1 {
            let mut parents = vec![Hash::default(); layer.len() / 2];
            engine.hash_many(64, layer.as_bytes(), &mut parents);
            layer = parents;
        }
        layer[0]
    }

    #[test]
    fn metal_sha2_matches_cpu_for_direct_hashes() {
        let gpu = MetalSha2HashEngine::new().unwrap();
        let cpu = Sha2::new();

        for &(size, count) in &[
            (0usize, 1usize),
            (1, 3),
            (31, 5),
            (32, 7),
            (55, 4),
            (56, 4),
            (57, 4),
            (63, 4),
            (64, 9),
            (65, 4),
            (96, 5),
            (256, 33),
            (5376, 17),
        ] {
            let input = random_messages(size, count);
            let mut expected = vec![Hash::default(); count];
            let mut actual = vec![Hash::default(); count];
            cpu.hash_many(size, &input, &mut expected);
            gpu.hash_many(size, &input, &mut actual);
            assert_eq!(expected, actual, "mismatch for size={size} count={count}");
        }
    }

    #[test]
    fn metal_sha2_matches_cpu_for_merkle_layers() {
        let gpu = MetalSha2HashEngine::new().unwrap();
        let cpu = Sha2::new();

        for &(leaf_size, count) in &[(64usize, 17usize), (256, 33), (5376, 19)] {
            let input = random_messages(leaf_size, count);
            let mut leaves_cpu = vec![Hash::default(); count];
            let mut leaves_gpu = vec![Hash::default(); count];
            cpu.hash_many(leaf_size, &input, &mut leaves_cpu);
            gpu.hash_many(leaf_size, &input, &mut leaves_gpu);
            assert_eq!(leaves_cpu, leaves_gpu);

            let root_cpu = merkle_root(&cpu, count, &leaves_cpu);
            let root_gpu = merkle_root(&gpu, count, &leaves_gpu);
            assert_eq!(root_cpu, root_gpu, "merkle mismatch for leaf_size={leaf_size}");
        }
    }

    #[test]
    fn metal_sha2_matches_sha2_engine_id() {
        let engine = MetalSha2HashEngine::new().unwrap();
        assert_eq!(engine.engine_id(), SHA2);
    }

    #[test]
    fn matrix_commit_roundtrip_with_registered_sha2_engine() {
        crate::register_ntt();
        let mut rng = ark_std::test_rng();
        let num_rows = 32usize;
        let num_cols = 8usize;
        let indices = [0usize, 3, 7, 7, 19, 31];

        let config = matrix_commit::Config::<Fr>::with_hash(SHA2, num_rows, num_cols);
        let ds = DomainSeparator::protocol(&config)
            .session(&format!("Test at {}:{}", file!(), line!()))
            .instance(&Empty);

        let matrix: Vec<_> = (0..config.size()).map(|_| Fr::rand(&mut rng)).collect();
        let submatrix: Vec<_> = indices
            .iter()
            .flat_map(|&index| {
                matrix
                    .chunks_exact(num_cols)
                    .nth(index)
                    .unwrap()
                    .iter()
                    .copied()
            })
            .collect();

        let mut prover_state = ProverState::new_std(&ds);
        let witness = config.commit(&mut prover_state, &matrix);
        config.open(&mut prover_state, &witness, &indices);
        let proof = prover_state.proof();

        let mut verifier_state = VerifierState::new_std(&ds, &proof);
        let commitment = config.receive_commitment(&mut verifier_state).unwrap();
        config
            .verify(&mut verifier_state, &commitment, &indices, &submatrix)
            .unwrap();
        verifier_state.check_eof().unwrap();
    }
}
