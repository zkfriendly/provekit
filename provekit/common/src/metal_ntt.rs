use {
    ark_bn254::{Fr, FrConfig},
    ark_ff::{BigInt, Field, Fp, MontBackend},
    metal::{
        objc::rc::autoreleasepool, Buffer, CommandQueue, CompileOptions, ComputePipelineState,
        Device, MTLResourceOptions, MTLSize, NSUInteger,
    },
    std::{
        collections::HashMap,
        env,
        ffi::c_void,
        marker::PhantomData,
        mem::size_of,
        sync::{Arc, Mutex, OnceLock},
        time::Instant,
    },
    tracing::info,
    whir::{
        algebra::ntt::{generator, ReedSolomon},
        engines::EngineId,
        hash::{Hash, SHA2},
        protocols::irs_commit::{AcceleratedCommit, AcceleratedCommitter, MatrixRows},
    },
};

#[derive(Clone, Copy, Debug, Default)]
pub struct MetalBn254Ntt;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct GpuField {
    limbs: [u64; 4],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct StageParams {
    total_butterflies: u64,
    row_len:           u64,
    half_len:          u64,
    step:              u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct PackParams {
    poly_size:          u64,
    row_len:            u64,
    interleaving_depth: u64,
    message_length:     u64,
    coeff_bits:         u32,
    expansion_bits:     u32,
    total_elements:     u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct TransposeParams {
    rows:           u64,
    cols:           u64,
    total_elements: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct FieldBytesParams {
    total_elements: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct HashManyParams {
    size:  u64,
    count: u64,
}

struct RootTable {
    buffer: Buffer,
}

struct EncodedMatrix {
    rows:   usize,
    cols:   usize,
    buffer: Buffer,
}

#[derive(Clone)]
struct MetalMatrixRows {
    rows:   usize,
    cols:   usize,
    buffer: Buffer,
}

struct MetalNttEngine {
    device:         Device,
    queue:          CommandQueue,
    pack:           ComputePipelineState,
    stage:          ComputePipelineState,
    transpose:      ComputePipelineState,
    encode_bytes:   ComputePipelineState,
    sha256:         ComputePipelineState,
    roots_by_order: Mutex<HashMap<usize, Arc<RootTable>>>,
}

static ENGINE: OnceLock<Result<Arc<MetalNttEngine>, String>> = OnceLock::new();

impl MetalBn254Ntt {
    const DEFAULT_MIN_CODEWORD_LENGTH: usize = 2;

    pub fn new() -> Result<Self, String> {
        if env::var_os("PROVEKIT_DISABLE_METAL_NTT").is_some() {
            return Err("Metal NTT disabled via PROVEKIT_DISABLE_METAL_NTT".into());
        }

        match ENGINE.get_or_init(|| MetalNttEngine::new().map(Arc::new)) {
            Ok(engine) => {
                info!(
                    device = engine.device.name(),
                    thread_execution_width = engine.stage.thread_execution_width(),
                    max_total_threads_per_threadgroup =
                        engine.stage.max_total_threads_per_threadgroup(),
                    "initialized Metal BN254 NTT backend"
                );
                trace_event(format_args!(
                    "init device={} thread_execution_width={} max_total_threads_per_threadgroup={}",
                    engine.device.name(),
                    engine.stage.thread_execution_width(),
                    engine.stage.max_total_threads_per_threadgroup()
                ));
                Ok(Self)
            }
            Err(err) => Err(err.clone()),
        }
    }

    fn engine(&self) -> Result<&Arc<MetalNttEngine>, String> {
        match ENGINE.get() {
            Some(Ok(engine)) => Ok(engine),
            Some(Err(err)) => Err(err.clone()),
            None => Err("metal engine not initialized".into()),
        }
    }

    fn min_codeword_length() -> usize {
        env::var("PROVEKIT_METAL_NTT_MIN_CODEWORD_LENGTH")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(Self::DEFAULT_MIN_CODEWORD_LENGTH)
    }

    fn should_accelerate(
        codeword_length: usize,
        interleaved_coeffs: &[&[Fr]],
        leaf_hash_id: Option<EngineId>,
    ) -> bool {
        if interleaved_coeffs.is_empty() {
            return false;
        }
        if codeword_length <= 1
            || !codeword_length.is_power_of_two()
            || codeword_length < Self::min_codeword_length()
        {
            return false;
        }
        if let Some(leaf_hash_id) = leaf_hash_id {
            if leaf_hash_id != SHA2 {
                return false;
            }
        }
        true
    }

    fn gpu_encode_artifact(
        &self,
        interleaved_coeffs: &[&[Fr]],
        codeword_length: usize,
        interleaving_depth: usize,
    ) -> Result<EncodedMatrix, String> {
        let total_started = Instant::now();
        let engine = self.engine()?;

        if interleaved_coeffs.is_empty() {
            return Ok(EncodedMatrix {
                rows:   0,
                cols:   0,
                buffer: engine.empty_buffer::<GpuField>(0),
            });
        }
        if !Self::should_accelerate(codeword_length, interleaved_coeffs, None) {
            return Err("problem size below GPU threshold or unsupported".into());
        }

        let poly_size = interleaved_coeffs[0].len();
        if !poly_size.is_multiple_of(interleaving_depth) {
            return Err("interleaving depth does not divide polynomial size".into());
        }
        let message_length = poly_size / interleaving_depth;
        if !codeword_length.is_multiple_of(message_length) {
            return Err("codeword length is not a multiple of the message length".into());
        }

        let rows = interleaved_coeffs.len() * interleaving_depth;
        let total_size = rows * codeword_length;
        let total_butterflies = total_size / 2;
        if total_size > u32::MAX as usize {
            return Err("GPU transpose launch exceeds current 32-bit grid limit".into());
        }
        if total_butterflies > u32::MAX as usize {
            return Err("GPU kernel launch exceeds current 32-bit grid limit".into());
        }
        trace_event(format_args!(
            "encode rows={} codeword_length={} interleaving_depth={} message_length={} \
             polynomials={}",
            rows,
            codeword_length,
            interleaving_depth,
            message_length,
            interleaved_coeffs.len()
        ));

        let pack_started = Instant::now();
        let mut coeffs = Vec::with_capacity(interleaved_coeffs.len() * poly_size);
        for (poly_index, poly) in interleaved_coeffs.iter().enumerate() {
            debug_assert_eq!(poly_index * poly_size, coeffs.len());
            coeffs.extend(poly.iter().copied().map(fr_to_gpu));
        }
        let pack_elapsed = pack_started.elapsed();

        let roots_started = Instant::now();
        let roots = engine.root_table(codeword_length)?;
        let roots_elapsed = roots_started.elapsed();

        let coeffs = engine.buffer_with_data(&coeffs);
        let mut current = engine.empty_buffer::<GpuField>(total_size);
        let mut scratch = engine.empty_buffer::<GpuField>(total_size);

        let gpu_started = Instant::now();
        let command_buffer = engine.queue.new_command_buffer();
        let pack_encoder = command_buffer.new_compute_command_encoder();
        pack_encoder.set_compute_pipeline_state(&engine.pack);
        let pack_params = PackParams {
            poly_size:          poly_size as u64,
            row_len:            codeword_length as u64,
            interleaving_depth: interleaving_depth as u64,
            message_length:     message_length as u64,
            coeff_bits:         message_length.trailing_zeros(),
            expansion_bits:     (codeword_length / message_length).trailing_zeros(),
            total_elements:     total_size as u64,
        };
        pack_encoder.set_buffer(0, Some(&coeffs), 0);
        pack_encoder.set_buffer(1, Some(&current), 0);
        pack_encoder.set_bytes(
            2,
            size_of::<PackParams>() as NSUInteger,
            (&pack_params as *const PackParams).cast::<c_void>(),
        );
        let pack_threads = engine.threads_per_threadgroup(&engine.pack, total_size);
        pack_encoder.dispatch_threads(
            MTLSize {
                width:  total_size as u64,
                height: 1,
                depth:  1,
            },
            pack_threads,
        );
        pack_encoder.end_encoding();

        let encoder = command_buffer.new_compute_command_encoder();
        encoder.set_compute_pipeline_state(&engine.stage);

        let stages = codeword_length.trailing_zeros() as usize;
        for stage in 0..stages {
            let len = 1usize << (stage + 1);
            let half = len / 2;
            let params = StageParams {
                total_butterflies: total_butterflies as u64,
                row_len:           codeword_length as u64,
                half_len:          half as u64,
                step:              (codeword_length / len) as u64,
            };

            encoder.set_buffer(0, Some(&current), 0);
            encoder.set_buffer(1, Some(&scratch), 0);
            encoder.set_buffer(2, Some(&roots.buffer), 0);
            encoder.set_bytes(
                3,
                size_of::<StageParams>() as NSUInteger,
                (&params as *const StageParams).cast::<c_void>(),
            );

            let threads_per_threadgroup =
                engine.threads_per_threadgroup(&engine.stage, total_butterflies);
            encoder.dispatch_threads(
                MTLSize {
                    width:  total_butterflies as u64,
                    height: 1,
                    depth:  1,
                },
                threads_per_threadgroup,
            );

            std::mem::swap(&mut current, &mut scratch);
        }

        encoder.end_encoding();
        let transpose_encoder = command_buffer.new_compute_command_encoder();
        transpose_encoder.set_compute_pipeline_state(&engine.transpose);
        let transpose_params = TransposeParams {
            rows:           rows as u64,
            cols:           codeword_length as u64,
            total_elements: total_size as u64,
        };
        transpose_encoder.set_buffer(0, Some(&current), 0);
        transpose_encoder.set_buffer(1, Some(&scratch), 0);
        transpose_encoder.set_bytes(
            2,
            size_of::<TransposeParams>() as NSUInteger,
            (&transpose_params as *const TransposeParams).cast::<c_void>(),
        );
        let transpose_threads = engine.threads_per_threadgroup(&engine.transpose, total_size);
        transpose_encoder.dispatch_threads(
            MTLSize {
                width:  total_size as u64,
                height: 1,
                depth:  1,
            },
            transpose_threads,
        );
        transpose_encoder.end_encoding();
        command_buffer.commit();
        command_buffer.wait_until_completed();
        let gpu_elapsed = gpu_started.elapsed();

        trace_event(format_args!(
            "encode timings codeword_length={} rows={} pack_us={} roots_us={} gpu_us={} \
             total_us={}",
            codeword_length,
            rows,
            pack_elapsed.as_micros(),
            roots_elapsed.as_micros(),
            gpu_elapsed.as_micros(),
            total_started.elapsed().as_micros()
        ));
        Ok(EncodedMatrix {
            rows:   codeword_length,
            cols:   rows,
            buffer: scratch,
        })
    }

    fn gpu_hash_rows(&self, matrix: &EncodedMatrix) -> Result<Vec<Hash>, String> {
        let total_started = Instant::now();
        let engine = self.engine()?;
        if matrix.rows == 0 {
            return Ok(Vec::new());
        }
        let total_elements = matrix.rows * matrix.cols;
        let row_size = matrix.cols * size_of::<GpuField>();
        if matrix.rows > u32::MAX as usize || total_elements > u32::MAX as usize {
            return Err("GPU row hashing launch exceeds current 32-bit grid limit".into());
        }

        let bytes_started = Instant::now();
        let bytes_buffer = engine.empty_buffer::<u8>(total_elements * size_of::<GpuField>());
        let hash_buffer = engine.empty_buffer::<Hash>(matrix.rows);
        let bytes_elapsed = bytes_started.elapsed();

        let params = FieldBytesParams {
            total_elements: total_elements as u64,
        };
        let hash_params = HashManyParams {
            size:  row_size as u64,
            count: matrix.rows as u64,
        };

        let gpu_started = Instant::now();
        let command_buffer = engine.queue.new_command_buffer();

        if total_elements > 0 {
            let encoder = command_buffer.new_compute_command_encoder();
            encoder.set_compute_pipeline_state(&engine.encode_bytes);
            encoder.set_buffer(0, Some(&matrix.buffer), 0);
            encoder.set_buffer(1, Some(&bytes_buffer), 0);
            encoder.set_bytes(
                2,
                size_of::<FieldBytesParams>() as NSUInteger,
                (&params as *const FieldBytesParams).cast::<c_void>(),
            );
            let threads = engine.threads_per_threadgroup(&engine.encode_bytes, total_elements);
            encoder.dispatch_threads(
                MTLSize {
                    width:  total_elements as u64,
                    height: 1,
                    depth:  1,
                },
                threads,
            );
            encoder.end_encoding();
        }

        let encoder = command_buffer.new_compute_command_encoder();
        encoder.set_compute_pipeline_state(&engine.sha256);
        encoder.set_buffer(0, Some(&bytes_buffer), 0);
        encoder.set_buffer(1, Some(&hash_buffer), 0);
        encoder.set_bytes(
            2,
            size_of::<HashManyParams>() as NSUInteger,
            (&hash_params as *const HashManyParams).cast::<c_void>(),
        );
        let threads = engine.threads_per_threadgroup(&engine.sha256, matrix.rows.max(1));
        encoder.dispatch_threads(
            MTLSize {
                width:  matrix.rows as u64,
                height: 1,
                depth:  1,
            },
            threads,
        );
        encoder.end_encoding();

        command_buffer.commit();
        command_buffer.wait_until_completed();
        let gpu_elapsed = gpu_started.elapsed();

        let readback_started = Instant::now();
        let hashes = engine.read_buffer::<Hash>(&hash_buffer, matrix.rows);
        let readback_elapsed = readback_started.elapsed();
        trace_event(format_args!(
            "hash timings rows={} cols={} encode_us={} gpu_us={} readback_us={} total_us={}",
            matrix.rows,
            matrix.cols,
            bytes_elapsed.as_micros(),
            gpu_elapsed.as_micros(),
            readback_elapsed.as_micros(),
            total_started.elapsed().as_micros()
        ));
        Ok(hashes)
    }

    fn gpu_encode(
        &self,
        interleaved_coeffs: &[&[Fr]],
        codeword_length: usize,
        interleaving_depth: usize,
    ) -> Result<Vec<Fr>, String> {
        let matrix =
            self.gpu_encode_artifact(interleaved_coeffs, codeword_length, interleaving_depth)?;
        let readback_started = Instant::now();
        let result = self
            .engine()?
            .read_buffer::<GpuField>(&matrix.buffer, matrix.rows * matrix.cols);
        let result: Vec<Fr> = result.into_iter().map(gpu_to_fr).collect();
        trace_event(format_args!(
            "readback timings codeword_length={} rows={} readback_us={}",
            codeword_length,
            matrix.rows,
            readback_started.elapsed().as_micros()
        ));
        Ok(result)
    }
}

impl ReedSolomon<Fr> for MetalBn254Ntt {
    fn interleaved_encode(
        &self,
        interleaved_coeffs: &[&[Fr]],
        codeword_length: usize,
        interleaving_depth: usize,
    ) -> Vec<Fr> {
        self.gpu_encode(interleaved_coeffs, codeword_length, interleaving_depth)
            .unwrap_or_else(|err| {
                panic!(
                    "Metal BN254 NTT execution failed for codeword_length={} \
                     interleaving_depth={}: {}",
                    codeword_length, interleaving_depth, err
                )
            })
    }
}

impl AcceleratedCommitter<Fr> for MetalBn254Ntt {
    fn try_commit_interleaved(
        &self,
        interleaved_coeffs: &[&[Fr]],
        codeword_length: usize,
        interleaving_depth: usize,
        leaf_hash_id: EngineId,
    ) -> Result<Option<AcceleratedCommit<Fr>>, String> {
        if !Self::should_accelerate(codeword_length, interleaved_coeffs, Some(leaf_hash_id)) {
            return Ok(None);
        }

        let matrix =
            self.gpu_encode_artifact(interleaved_coeffs, codeword_length, interleaving_depth)?;
        let leaf_hashes = self.gpu_hash_rows(&matrix)?;
        let rows = Arc::new(MetalMatrixRows {
            rows:   matrix.rows,
            cols:   matrix.cols,
            buffer: matrix.buffer,
        });
        Ok(Some(AcceleratedCommit {
            matrix: rows,
            leaf_hashes,
        }))
    }
}

impl std::fmt::Debug for MetalMatrixRows {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetalMatrixRows")
            .field("rows", &self.rows)
            .field("cols", &self.cols)
            .finish()
    }
}

impl MatrixRows<Fr> for MetalMatrixRows {
    fn len(&self) -> usize {
        self.rows * self.cols
    }

    fn read_rows(&self, indices: &[usize]) -> Vec<Fr> {
        let fields = unsafe {
            std::slice::from_raw_parts(self.buffer.contents().cast::<GpuField>(), self.len())
        };
        let mut out = Vec::with_capacity(indices.len() * self.cols);
        for &row in indices {
            assert!(row < self.rows, "row index out of bounds");
            let start = row * self.cols;
            let end = start + self.cols;
            out.extend(fields[start..end].iter().copied().map(gpu_to_fr));
        }
        out
    }
}

impl MetalNttEngine {
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
            let pack = library
                .get_function("pack_coefficients", None)
                .map_err(|err| err.to_string())
                .and_then(|function| device.new_compute_pipeline_state_with_function(&function))?;
            let stage = library
                .get_function("stage_ntt", None)
                .map_err(|err| err.to_string())
                .and_then(|function| device.new_compute_pipeline_state_with_function(&function))?;
            let transpose = library
                .get_function("transpose_matrix", None)
                .map_err(|err| err.to_string())
                .and_then(|function| device.new_compute_pipeline_state_with_function(&function))?;
            let encode_bytes = library
                .get_function("encode_field_rows_le", None)
                .map_err(|err| err.to_string())
                .and_then(|function| device.new_compute_pipeline_state_with_function(&function))?;
            let sha256 = library
                .get_function("sha256_many", None)
                .map_err(|err| err.to_string())
                .and_then(|function| device.new_compute_pipeline_state_with_function(&function))?;
            let queue = device.new_command_queue();

            Ok(Self {
                device,
                queue,
                pack,
                stage,
                transpose,
                encode_bytes,
                sha256,
                roots_by_order: Mutex::new(HashMap::new()),
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

    fn read_buffer<T: Copy>(&self, buffer: &Buffer, len: usize) -> Vec<T> {
        let ptr = buffer.contents().cast::<T>();
        unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec()
    }

    fn threads_per_threadgroup(
        &self,
        pipeline: &ComputePipelineState,
        work_items: usize,
    ) -> MTLSize {
        let width = pipeline
            .thread_execution_width()
            .min(pipeline.max_total_threads_per_threadgroup())
            .min(work_items as u64)
            .max(1);
        MTLSize {
            width,
            height: 1,
            depth: 1,
        }
    }

    fn root_table(&self, codeword_length: usize) -> Result<Arc<RootTable>, String> {
        let mut cache = self.roots_by_order.lock().unwrap();
        if let Some(table) = cache.get(&codeword_length) {
            trace_event(format_args!(
                "roots cache hit codeword_length={codeword_length}"
            ));
            return Ok(Arc::clone(table));
        }

        let root = generator::<Fr>(codeword_length)
            .ok_or_else(|| format!("no primitive root for order {codeword_length}"))?;
        let mut roots = Vec::with_capacity(codeword_length / 2);
        let mut current = Fr::ONE;
        for _ in 0..(codeword_length / 2) {
            roots.push(fr_to_gpu(current));
            current *= root;
        }

        let table = Arc::new(RootTable {
            buffer: self.buffer_with_data(&roots),
        });
        cache.insert(codeword_length, Arc::clone(&table));
        trace_event(format_args!(
            "roots cache miss codeword_length={codeword_length}"
        ));
        Ok(table)
    }
}

fn trace_event(args: std::fmt::Arguments<'_>) {
    if env::var_os("PROVEKIT_METAL_NTT_TRACE").is_some() {
        eprintln!("[provekit-metal-ntt] {args}");
    }
}

fn fr_to_gpu(value: Fr) -> GpuField {
    GpuField { limbs: value.0 .0 }
}

fn gpu_to_fr(value: GpuField) -> Fr {
    Fp::<MontBackend<FrConfig, 4>, 4>(BigInt(value.limbs), PhantomData)
}

const SHADER_SOURCE: &str = r#"
#include <metal_stdlib>
using namespace metal;

struct Fe {
    ulong limbs[4];
};

struct StageParams {
    ulong total_butterflies;
    ulong row_len;
    ulong half_len;
    ulong step;
};

struct PackParams {
    ulong poly_size;
    ulong row_len;
    ulong interleaving_depth;
    ulong message_length;
    uint coeff_bits;
    uint expansion_bits;
    ulong total_elements;
};

struct TransposeParams {
    ulong rows;
    ulong cols;
    ulong total_elements;
};

struct FieldBytesParams {
    ulong total_elements;
};

struct HashManyParams {
    ulong size;
    ulong count;
};

constant ulong MODULUS[4] = {
    0x43e1f593f0000001ul,
    0x2833e84879b97091ul,
    0xb85045b68181585dul,
    0x30644e72e131a029ul
};

constant ulong N0_INV = 0xc2e1f593effffffful;
constant Fe FE_ONE = {{1ul, 0ul, 0ul, 0ul}};

constant uint SHA256_K[64] = {
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

inline uint reverse_bits_u32(uint x) {
    x = ((x & 0x55555555u) << 1) | ((x >> 1) & 0x55555555u);
    x = ((x & 0x33333333u) << 2) | ((x >> 2) & 0x33333333u);
    x = ((x & 0x0f0f0f0fu) << 4) | ((x >> 4) & 0x0f0f0f0fu);
    x = ((x & 0x00ff00ffu) << 8) | ((x >> 8) & 0x00ff00ffu);
    return (x << 16) | (x >> 16);
}

inline bool geq_mod(Fe a) {
    for (int i = 3; i >= 0; --i) {
        if (a.limbs[i] > MODULUS[i]) {
            return true;
        }
        if (a.limbs[i] < MODULUS[i]) {
            return false;
        }
    }
    return true;
}

inline Fe sub_modulus(Fe a) {
    Fe out;
    ulong borrow = 0;
    for (uint i = 0; i < 4; ++i) {
        ulong tmp = a.limbs[i] - MODULUS[i] - borrow;
        borrow = (a.limbs[i] < MODULUS[i] + borrow) ? 1ul : 0ul;
        out.limbs[i] = tmp;
    }
    return out;
}

inline Fe add_mod(Fe a, Fe b) {
    Fe out;
    ulong carry = 0;
    for (uint i = 0; i < 4; ++i) {
        ulong sum = a.limbs[i] + b.limbs[i];
        ulong c1 = sum < a.limbs[i] ? 1ul : 0ul;
        ulong sum2 = sum + carry;
        ulong c2 = sum2 < sum ? 1ul : 0ul;
        out.limbs[i] = sum2;
        carry = c1 + c2;
    }
    if (carry != 0 || geq_mod(out)) {
        out = sub_modulus(out);
    }
    return out;
}

inline Fe sub_mod(Fe a, Fe b) {
    Fe out;
    ulong borrow = 0;
    for (uint i = 0; i < 4; ++i) {
        ulong tmp = a.limbs[i] - b.limbs[i] - borrow;
        ulong next_borrow = (a.limbs[i] < b.limbs[i] + borrow) ? 1ul : 0ul;
        out.limbs[i] = tmp;
        borrow = next_borrow;
    }
    if (borrow != 0) {
        ulong carry = 0;
        for (uint i = 0; i < 4; ++i) {
            ulong sum = out.limbs[i] + MODULUS[i];
            ulong c1 = sum < out.limbs[i] ? 1ul : 0ul;
            ulong sum2 = sum + carry;
            ulong c2 = sum2 < sum ? 1ul : 0ul;
            out.limbs[i] = sum2;
            carry = c1 + c2;
        }
    }
    return out;
}

inline Fe mont_mul(Fe a, Fe b) {
    ulong t[5] = {0, 0, 0, 0, 0};

    for (uint i = 0; i < 4; ++i) {
        ulong carry = 0;
        for (uint j = 0; j < 4; ++j) {
            ulong lo = a.limbs[j] * b.limbs[i];
            ulong hi = mulhi(a.limbs[j], b.limbs[i]);

            ulong sum = t[j] + lo;
            hi += (sum < t[j]) ? 1ul : 0ul;

            ulong sum2 = sum + carry;
            hi += (sum2 < sum) ? 1ul : 0ul;

            t[j] = sum2;
            carry = hi;
        }
        t[4] = carry;

        ulong m = t[0] * N0_INV;
        carry = 0;

        {
            ulong lo = m * MODULUS[0];
            ulong hi = mulhi(m, MODULUS[0]);
            ulong sum = t[0] + lo;
            hi += (sum < t[0]) ? 1ul : 0ul;
            ulong sum2 = sum + carry;
            hi += (sum2 < sum) ? 1ul : 0ul;
            carry = hi;
        }

        for (uint j = 1; j < 4; ++j) {
            ulong lo = m * MODULUS[j];
            ulong hi = mulhi(m, MODULUS[j]);
            ulong sum = t[j] + lo;
            hi += (sum < t[j]) ? 1ul : 0ul;
            ulong sum2 = sum + carry;
            hi += (sum2 < sum) ? 1ul : 0ul;
            t[j - 1] = sum2;
            carry = hi;
        }

        ulong sum = t[4] + carry;
        ulong c = (sum < t[4]) ? 1ul : 0ul;
        t[3] = sum;
        t[4] = c;
    }

    Fe out;
    out.limbs[0] = t[0];
    out.limbs[1] = t[1];
    out.limbs[2] = t[2];
    out.limbs[3] = t[3];
    if (t[4] != 0 || geq_mod(out)) {
        out = sub_modulus(out);
    }
    return out;
}

inline Fe from_mont(Fe a) {
    return mont_mul(a, FE_ONE);
}

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

kernel void pack_coefficients(
    device const Fe* coeffs [[buffer(0)]],
    device Fe* output [[buffer(1)]],
    constant PackParams& params [[buffer(2)]],
    uint gid [[thread_position_in_grid]]
) {
    if ((ulong)gid >= params.total_elements) {
        return;
    }

    ulong row = ((ulong)gid) / params.row_len;
    ulong position = ((ulong)gid) - row * params.row_len;
    ulong expansion_mask = (1ul << params.expansion_bits) - 1ul;
    if ((position & expansion_mask) != 0) {
        Fe zero = {{0ul, 0ul, 0ul, 0ul}};
        output[gid] = zero;
        return;
    }

    ulong poly_index = row / params.interleaving_depth;
    ulong block_index = row - poly_index * params.interleaving_depth;
    uint packed_index = (uint)(position >> params.expansion_bits);
    uint coeff_index = params.coeff_bits == 0
        ? 0u
        : (reverse_bits_u32(packed_index) >> (32 - params.coeff_bits));
    ulong src = poly_index * params.poly_size + block_index * params.message_length + coeff_index;
    output[gid] = coeffs[src];
}

kernel void stage_ntt(
    device const Fe* input [[buffer(0)]],
    device Fe* output [[buffer(1)]],
    device const Fe* roots [[buffer(2)]],
    constant StageParams& params [[buffer(3)]],
    uint gid [[thread_position_in_grid]]
) {
    if ((ulong)gid >= params.total_butterflies) {
        return;
    }

    ulong butterflies_per_row = params.row_len >> 1;
    ulong row = ((ulong)gid) / butterflies_per_row;
    ulong local = ((ulong)gid) - row * butterflies_per_row;
    ulong group = local / params.half_len;
    ulong k = local - group * params.half_len;

    ulong i0 = row * params.row_len + group * (params.half_len << 1) + k;
    ulong i1 = i0 + params.half_len;

    Fe even = input[i0];
    Fe odd = input[i1];
    Fe twiddle = roots[k * params.step];
    Fe twiddled = mont_mul(odd, twiddle);

    output[i0] = add_mod(even, twiddled);
    output[i1] = sub_mod(even, twiddled);
}

kernel void transpose_matrix(
    device const Fe* input [[buffer(0)]],
    device Fe* output [[buffer(1)]],
    constant TransposeParams& params [[buffer(2)]],
    uint gid [[thread_position_in_grid]]
) {
    if ((ulong)gid >= params.total_elements) {
        return;
    }

    ulong row = ((ulong)gid) / params.cols;
    ulong col = ((ulong)gid) - row * params.cols;
    ulong dst = col * params.rows + row;
    output[dst] = input[gid];
}

kernel void encode_field_rows_le(
    device const Fe* input [[buffer(0)]],
    device uchar* output [[buffer(1)]],
    constant FieldBytesParams& params [[buffer(2)]],
    uint gid [[thread_position_in_grid]]
) {
    if ((ulong)gid >= params.total_elements) {
        return;
    }

    Fe canonical = from_mont(input[gid]);
    ulong byte_offset = (ulong)gid * 32ul;
    for (uint limb = 0; limb < 4; ++limb) {
        ulong value = canonical.limbs[limb];
        for (uint byte = 0; byte < 8; ++byte) {
            output[byte_offset + limb * 8ul + byte] = uchar((value >> (byte * 8u)) & 0xfful);
        }
    }
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
            uint t1 = h + big_sigma1(e) + ch(e, f, g) + SHA256_K[i] + w[i];
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
    use {
        super::MetalBn254Ntt,
        ark_bn254::Fr,
        ark_ff::{AdditiveGroup, UniformRand},
        whir::{
            algebra::{
                embedding::Identity,
                ntt::{ntt_batch, transpose, ReedSolomon},
            },
            hash::{Hash, HashEngine, Sha2, SHA2},
            protocols::{irs_commit::AcceleratedCommitter, matrix_commit::Encodable},
            transcript::{codecs::Empty, DomainSeparator, ProverState, VerifierState},
        },
    };

    fn reference_interleaved_encode(
        interleaved_coeffs: &[&[Fr]],
        codeword_length: usize,
        interleaving_depth: usize,
    ) -> Vec<Fr> {
        if interleaved_coeffs.is_empty() {
            return Vec::new();
        }

        let poly_size = interleaved_coeffs[0].len();
        let message_length = poly_size / interleaving_depth;
        let per_poly_size = codeword_length * interleaving_depth;
        let total_size = per_poly_size * interleaved_coeffs.len();

        let mut result = vec![Fr::ZERO; total_size];
        for (poly_index, poly) in interleaved_coeffs.iter().enumerate() {
            for (block_index, block) in poly.chunks_exact(message_length).enumerate() {
                let dst = poly_index * per_poly_size + block_index * codeword_length;
                result[dst..dst + message_length].copy_from_slice(block);
            }
        }

        ntt_batch(&mut result, codeword_length);
        transpose(
            &mut result,
            interleaved_coeffs.len() * interleaving_depth,
            codeword_length,
        );
        result
    }

    fn hash_rows_cpu(matrix: &[Fr], num_rows: usize, num_cols: usize) -> Vec<Hash> {
        let engine = Sha2::new();
        let mut encoder = <Fr as Encodable>::encoder();
        let bytes = encoder.encode(matrix);
        let mut out = vec![Hash::default(); num_rows];
        engine.hash_many(num_cols * Fr::encoded_size(), bytes, &mut out);
        out
    }

    #[test]
    fn metal_matches_cpu_for_small_case() {
        let gpu = MetalBn254Ntt::new().unwrap();
        eprintln!(
            "using Metal device: {}",
            gpu.engine().unwrap().device.name()
        );

        let mut rng = ark_std::test_rng();
        let coeffs: Vec<_> = (0..(1 << 12)).map(|_| Fr::rand(&mut rng)).collect();
        let cpu = reference_interleaved_encode(&[&coeffs], 1 << 11, 1 << 1);
        let gpu = gpu.interleaved_encode(&[&coeffs], 1 << 11, 1 << 1);
        assert_eq!(cpu, gpu);
    }

    #[test]
    fn metal_accelerated_commit_matches_cpu() {
        let gpu = MetalBn254Ntt::new().unwrap();
        let mut rng = ark_std::test_rng();
        let coeffs_a: Vec<_> = (0..32).map(|_| Fr::rand(&mut rng)).collect();
        let coeffs_b: Vec<_> = (0..32).map(|_| Fr::rand(&mut rng)).collect();
        let coeffs = [&coeffs_a[..], &coeffs_b[..]];
        let codeword_length = 32usize;
        let interleaving_depth = 2usize;

        let accelerated = gpu
            .try_commit_interleaved(&coeffs, codeword_length, interleaving_depth, SHA2)
            .unwrap()
            .unwrap();
        let cpu_matrix = reference_interleaved_encode(&coeffs, codeword_length, interleaving_depth);
        let expected_hashes = hash_rows_cpu(
            &cpu_matrix,
            codeword_length,
            coeffs.len() * interleaving_depth,
        );
        assert_eq!(accelerated.leaf_hashes, expected_hashes);

        let expected_rows = [0usize, 3, 3, 17]
            .into_iter()
            .flat_map(|row| {
                let start = row * coeffs.len() * interleaving_depth;
                cpu_matrix[start..start + coeffs.len() * interleaving_depth]
                    .iter()
                    .copied()
            })
            .collect::<Vec<_>>();
        assert_eq!(accelerated.matrix.read_rows(&[0, 3, 3, 17]), expected_rows);
    }

    #[test]
    fn irs_commit_roundtrip_uses_accelerated_matrix() {
        crate::register_ntt();

        let config = whir::protocols::irs_commit::Config::<Identity<Fr>>::new(
            20.0, true, SHA2, 1, 32, 2, 0.5,
        );
        let ds = DomainSeparator::protocol(&config)
            .session(&format!("Test at {}:{}", file!(), line!()))
            .instance(&Empty);

        let mut rng = ark_std::test_rng();
        let vector: Vec<_> = (0..32).map(|_| Fr::rand(&mut rng)).collect();

        let mut prover_state = ProverState::new_std(&ds);
        let witness = config.commit(&mut prover_state, &[vector.as_slice()]);
        assert!(witness.uses_accelerated_matrix());
        let evals = config.open(&mut prover_state, &[&witness]);
        let proof = prover_state.proof();

        let mut verifier_state = VerifierState::new_std(&ds, &proof);
        let commitment = config.receive_commitment(&mut verifier_state).unwrap();
        let verified = config.verify(&mut verifier_state, &[&commitment]).unwrap();
        assert_eq!(verified, evals);
        verifier_state.check_eof().unwrap();
    }
}
