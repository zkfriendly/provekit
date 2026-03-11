use {
    cudarc::{
        driver::{
            CudaContext, CudaFunction, CudaSlice, CudaStream, DeviceRepr, DriverError,
            LaunchConfig, PushKernelArg,
        },
        nvrtc::{compile_ptx_with_opts, CompileOptions},
    },
    sha2::digest::const_oid::{AssociatedOid, ObjectIdentifier},
    std::{
        collections::hash_map::DefaultHasher,
        env,
        fs,
        hash::{Hash as _, Hasher},
        mem::size_of,
        path::PathBuf,
        sync::{Arc, Mutex, OnceLock},
        time::Instant,
    },
    tracing::info,
    whir::hash::{Hash, HashEngine, Sha2},
};

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct HashManyParams {
    size:  u64,
    count: u64,
}

unsafe impl DeviceRepr for HashManyParams {}

struct CudaSha2Runtime {
    ctx:    Arc<CudaContext>,
    kernel: CudaFunction,
    buffers: Mutex<Vec<Sha2Buffers>>,
}

static RUNTIME: OnceLock<Result<Arc<CudaSha2Runtime>, String>> = OnceLock::new();
static PREFERRED_BATCH_SIZE: OnceLock<usize> = OnceLock::new();

struct Sha2Buffers {
    stream: Arc<CudaStream>,
    input:  Option<CudaSlice<u8>>,
    output: Option<CudaSlice<u8>>,
}

struct Sha2Lease<'a> {
    runtime:  &'a CudaSha2Runtime,
    buffers: Option<Sha2Buffers>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct CudaSha2HashEngine;

impl CudaSha2HashEngine {
    const BLOCK_DIM: u32 = 64;

    pub fn new() -> Result<Self, String> {
        if env::var_os("PROVEKIT_DISABLE_CUDA_SHA2").is_some() {
            return Err("CUDA SHA2 disabled via PROVEKIT_DISABLE_CUDA_SHA2".into());
        }

        match RUNTIME.get_or_init(|| CudaSha2Runtime::new().map(Arc::new)) {
            Ok(runtime) => {
                let (major, minor) = runtime.ctx.compute_capability().map_err(|err| err.to_string())?;
                info!(
                    device = runtime.ctx.name().map_err(|err| err.to_string())?,
                    compute_capability = format!("{major}.{minor}"),
                    preferred_batch_size = preferred_batch_size(),
                    "initialized CUDA SHA2 backend"
                );
                trace_event(format_args!(
                    "init device={} compute_capability={major}.{minor} preferred_batch_size={}",
                    runtime.ctx.name().map_err(|err| err.to_string())?,
                    preferred_batch_size()
                ));
                Ok(Self)
            }
            Err(err) => Err(err.clone()),
        }
    }

    fn runtime(&self) -> Result<&Arc<CudaSha2Runtime>, String> {
        match RUNTIME.get() {
            Some(Ok(runtime)) => Ok(runtime),
            Some(Err(err)) => Err(err.clone()),
            None => Err("cuda sha2 runtime not initialized".into()),
        }
    }

    fn gpu_hash_many(&self, size: usize, input: &[u8], output: &mut [Hash]) -> Result<(), String> {
        let total_started = Instant::now();
        let runtime = self.runtime()?;
        let count = output.len();

        if count == 0 {
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
            return Err("CUDA SHA2 launch exceeds current 32-bit grid limit".into());
        }
        if size == 0 {
            Sha2::new().hash_many(size, input, output);
            return Ok(());
        }

        let encode_started = Instant::now();
        let mut buffers = runtime.checkout_buffers()?;
        buffers.ensure_input_buffer(input.len())?;
        buffers.ensure_output_buffer(count * size_of::<Hash>())?;
        let buffers_inner = buffers.buffers.as_mut().unwrap();
        let stream = Arc::clone(&buffers_inner.stream);
        let input_dev = buffers_inner.input.as_mut().unwrap();
        let output_dev = buffers_inner.output.as_mut().unwrap();
        let mut input_view = input_dev.slice_mut(..input.len());
        let mut output_view = output_dev.slice_mut(..count * size_of::<Hash>());
        stream.memcpy_htod(input, &mut input_view).map_err(driver_err)?;
        let params = HashManyParams {
            size:  size as u64,
            count: count as u64,
        };
        let encode_elapsed = encode_started.elapsed();

        let gpu_started = Instant::now();
        let cfg = LaunchConfig {
            grid_dim: ((count as u32).div_ceil(Self::BLOCK_DIM), 1, 1),
            block_dim: (Self::BLOCK_DIM, 1, 1),
            shared_mem_bytes: 0,
        };
        let input_read_view = input_view.as_view();
        let mut launch = stream.launch_builder(&runtime.kernel);
        launch.arg(&input_read_view);
        launch.arg(&mut output_view);
        launch.arg(&params);
        unsafe { launch.launch(cfg) }.map_err(driver_err)?;
        stream.synchronize().map_err(driver_err)?;
        let gpu_elapsed = gpu_started.elapsed();

        let readback_started = Instant::now();
        let mut bytes = vec![0u8; count * size_of::<Hash>()];
        stream.memcpy_dtoh(&output_view, &mut bytes).map_err(driver_err)?;
        stream.synchronize().map_err(driver_err)?;
        for (dst, chunk) in output.iter_mut().zip(bytes.chunks_exact(size_of::<Hash>())) {
            dst.0.copy_from_slice(chunk);
        }
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

impl HashEngine for CudaSha2HashEngine {
    fn name(&self) -> std::borrow::Cow<'_, str> {
        "cuda-sha2".into()
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
                "CUDA SHA2 execution failed for size={} count={}: {}",
                size,
                output.len(),
                err
            )
        });
    }
}

impl CudaSha2Runtime {
    fn new() -> Result<Self, String> {
        let ctx = CudaContext::new(0).map_err(driver_err)?;
        let (major, minor) = ctx.compute_capability().map_err(driver_err)?;
        let ptx = compile_cached_ptx(
            "sha2",
            CUDA_SHA2_SOURCE,
            arch_for_compute_capability(major, minor),
        )?;
        let module = ctx.load_module(ptx).map_err(driver_err)?;
        let kernel = module.load_function("sha256_many").map_err(driver_err)?;

        Ok(Self {
            ctx,
            kernel,
            buffers: Mutex::new(Vec::new()),
        })
    }

    fn checkout_buffers(&self) -> Result<Sha2Lease<'_>, String> {
        let buffers = self.buffers.lock().unwrap().pop();
        let buffers = match buffers {
            Some(buffers) => buffers,
            None => Sha2Buffers::new(Arc::clone(&self.ctx))?,
        };
        Ok(Sha2Lease {
            runtime: self,
            buffers: Some(buffers),
        })
    }
}

fn arch_for_compute_capability(major: i32, minor: i32) -> Option<&'static str> {
    match (major, minor) {
        (5, 0) => Some("compute_50"),
        (5, 2) => Some("compute_52"),
        (6, 0) => Some("compute_60"),
        (6, 1) => Some("compute_61"),
        (7, 0) => Some("compute_70"),
        (7, 5) => Some("compute_75"),
        (8, 0) => Some("compute_80"),
        (8, 6) => Some("compute_86"),
        (8, 9) => Some("compute_89"),
        (9, 0) => Some("compute_90"),
        _ => None,
    }
}

fn driver_err(err: DriverError) -> String {
    err.to_string()
}

impl Sha2Buffers {
    fn new(ctx: Arc<CudaContext>) -> Result<Self, String> {
        Ok(Self {
            stream: ctx.new_stream().map_err(driver_err)?,
            input: None,
            output: None,
        })
    }

    fn ensure_input_buffer(&mut self, len: usize) -> Result<(), String> {
        let needs_alloc = self.input.as_ref().is_none_or(|buffer| buffer.len() < len);
        if needs_alloc {
            self.input = Some(self.stream.alloc_zeros::<u8>(len).map_err(driver_err)?);
        }
        Ok(())
    }

    fn ensure_output_buffer(&mut self, len: usize) -> Result<(), String> {
        let needs_alloc = self.output.as_ref().is_none_or(|buffer| buffer.len() < len);
        if needs_alloc {
            self.output = Some(self.stream.alloc_zeros::<u8>(len).map_err(driver_err)?);
        }
        Ok(())
    }

}

impl Drop for Sha2Lease<'_> {
    fn drop(&mut self) {
        if let Some(buffers) = self.buffers.take() {
            self.runtime.buffers.lock().unwrap().push(buffers);
        }
    }
}

impl Sha2Lease<'_> {
    fn ensure_input_buffer(&mut self, len: usize) -> Result<(), String> {
        self.buffers.as_mut().unwrap().ensure_input_buffer(len)
    }

    fn ensure_output_buffer(&mut self, len: usize) -> Result<(), String> {
        self.buffers.as_mut().unwrap().ensure_output_buffer(len)
    }

}

fn compile_cached_ptx(
    tag: &str,
    source: &str,
    arch: Option<&'static str>,
) -> Result<cudarc::nvrtc::Ptx, String> {
    let cache_path = ptx_cache_path(tag, source, arch);
    if let Some(path) = cache_path.as_ref() {
        if let Ok(ptx) = fs::read_to_string(path) {
            return Ok(cudarc::nvrtc::Ptx::from_src(ptx));
        }
    }
    let ptx = compile_ptx_with_opts(
        source,
        CompileOptions {
            arch,
            ..Default::default()
        },
    )
    .map_err(|err| err.to_string())?;
    if let Some(path) = cache_path {
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(path, ptx.to_src());
    }
    Ok(ptx)
}

fn ptx_cache_path(tag: &str, source: &str, arch: Option<&str>) -> Option<PathBuf> {
    let cache_root = env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))?;
    let mut hasher = DefaultHasher::new();
    tag.hash(&mut hasher);
    arch.unwrap_or("generic").hash(&mut hasher);
    source.hash(&mut hasher);
    Some(
        cache_root
            .join("provekit")
            .join("cuda")
            .join(format!("{tag}-{}-{:016x}.ptx", arch.unwrap_or("generic"), hasher.finish())),
    )
}

fn trace_event(args: std::fmt::Arguments<'_>) {
    if env::var_os("PROVEKIT_CUDA_SHA2_TRACE").is_some() {
        eprintln!("[provekit-cuda-sha2] {args}");
    }
}

fn preferred_batch_size() -> usize {
    *PREFERRED_BATCH_SIZE.get_or_init(|| {
        env::var("PROVEKIT_CUDA_SHA2_PREFERRED_BATCH_SIZE")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|&value| value > 0)
            .unwrap_or(256)
    })
}

const CUDA_SHA2_SOURCE: &str = r#"
typedef unsigned int uint;
typedef unsigned long long ulong;

struct HashManyParams {
    ulong size;
    ulong count;
};

__device__ __constant__ uint K[64] = {
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

__device__ __forceinline__ uint rotr32(uint x, uint n) {
    return (x >> n) | (x << (32 - n));
}

__device__ __forceinline__ uint ch(uint x, uint y, uint z) {
    return (x & y) ^ ((~x) & z);
}

__device__ __forceinline__ uint maj(uint x, uint y, uint z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

__device__ __forceinline__ uint big_sigma0(uint x) {
    return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22);
}

__device__ __forceinline__ uint big_sigma1(uint x) {
    return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25);
}

__device__ __forceinline__ uint small_sigma0(uint x) {
    return rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3);
}

__device__ __forceinline__ uint small_sigma1(uint x) {
    return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10);
}

extern "C" __global__ void sha256_many(
    const unsigned char* input,
    unsigned char* output,
    HashManyParams params
) {
    ulong gid = (ulong)blockIdx.x * (ulong)blockDim.x + (ulong)threadIdx.x;
    if (gid >= params.count) {
        return;
    }

    ulong offset = gid * params.size;
    ulong total_blocks = (params.size + 9ull + 63ull) / 64ull;
    ulong total_padded_len = total_blocks * 64ull;
    ulong bit_len = params.size * 8ull;

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
                ulong idx = block * 64ull + (ulong)i * 4ull + (ulong)j;
                unsigned char byte = 0u;
                if (idx < params.size) {
                    byte = input[offset + idx];
                } else if (idx == params.size) {
                    byte = 0x80u;
                } else if (idx >= total_padded_len - 8ull) {
                    uint shift = (uint)((total_padded_len - 1ull - idx) * 8ull);
                    byte = (unsigned char)((bit_len >> shift) & 0xffull);
                }
                word = (word << 8) | (uint)byte;
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

    unsigned char* out = output + gid * 32ull;
    uint digest[8] = {h0, h1, h2, h3, h4, h5, h6, h7};
    for (uint i = 0; i < 8; ++i) {
        out[i * 4 + 0] = (unsigned char)((digest[i] >> 24) & 0xffu);
        out[i * 4 + 1] = (unsigned char)((digest[i] >> 16) & 0xffu);
        out[i * 4 + 2] = (unsigned char)((digest[i] >> 8) & 0xffu);
        out[i * 4 + 3] = (unsigned char)(digest[i] & 0xffu);
    }
}
"#;

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use {
        super::CudaSha2HashEngine,
        whir::hash::{Hash, HashEngine, Sha2, SHA2},
        whir::engines::Engine as _,
    };

    fn random_messages(size: usize, count: usize) -> Vec<u8> {
        let mut rng = ark_std::test_rng();
        let mut input = vec![0u8; size * count];
        use ark_std::rand::RngCore;
        rng.fill_bytes(&mut input);
        input
    }

    #[test]
    fn cuda_sha2_matches_cpu_for_direct_hashes() {
        let gpu = CudaSha2HashEngine::new().unwrap();
        let cpu = Sha2::new();

        for &(size, count) in &[(1usize, 3usize), (32, 7), (64, 9), (65, 4), (256, 17)] {
            let input = random_messages(size, count);
            let mut expected = vec![Hash::default(); count];
            let mut actual = vec![Hash::default(); count];
            cpu.hash_many(size, &input, &mut expected);
            gpu.hash_many(size, &input, &mut actual);
            assert_eq!(expected, actual, "mismatch for size={size} count={count}");
        }
    }

    #[test]
    fn cuda_sha2_matches_sha2_engine_id() {
        let engine = CudaSha2HashEngine::new().unwrap();
        assert_eq!(engine.engine_id(), SHA2);
    }
}
