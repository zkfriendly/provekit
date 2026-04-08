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
        protocols::{
            irs_commit::{AcceleratedCommit, AcceleratedCommitter, MatrixRows},
            matrix_commit::Encodable,
        },
    },
};

#[derive(Clone, Copy, Debug, Default)]
pub struct MetalBn254Ntt;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct GpuField {
    limbs: [u64; 4],
}

const GPU_FIELD_MODULUS: [u64; 4] = [
    0x43e1f593f0000001,
    0x2833e84879b97091,
    0xb85045b68181585d,
    0x30644e72e131a029,
];

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct BitReverseConfig {
    length: u32,
    log_n:  u32,
    _pad0:  u32,
    _pad1:  u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct StageConfig {
    half_m:         u32,
    twiddle_offset: u32,
    _pad0:          u32,
    _pad1:          u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct TransposeParams {
    rows:           u32,
    cols:           u32,
    total_elements: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct FieldBytesParams {
    total_elements: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct HashManyParams {
    size:  u32,
    count: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
#[allow(dead_code)]
struct FieldMulParams {
    count: u32,
}

struct RootTable {
    buffer: Buffer,
}

enum EncodedMatrixStorage {
    Field(Buffer),
}

struct EncodedMatrix {
    rows:    usize,
    cols:    usize,
    storage: EncodedMatrixStorage,
}

#[derive(Clone)]
enum MatrixStorage {
    Field(Buffer),
}

#[derive(Clone)]
struct MetalMatrixRows {
    rows:    usize,
    cols:    usize,
    storage: MatrixStorage,
}

struct MetalNttEngine {
    device:       Device,
    queue:        CommandQueue,
    bit_reverse:  ComputePipelineState,
    stage:        ComputePipelineState,
    #[allow(dead_code)]
    field_mul:    ComputePipelineState,
    transpose:    ComputePipelineState,
    encode_bytes: ComputePipelineState,
    sha256:       ComputePipelineState,
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
        self.gpu_encode_artifact_with_path(interleaved_coeffs, codeword_length, interleaving_depth)
    }

    fn gpu_encode_artifact_with_path(
        &self,
        interleaved_coeffs: &[&[Fr]],
        codeword_length: usize,
        interleaving_depth: usize,
    ) -> Result<EncodedMatrix, String> {
        let total_started = Instant::now();
        let engine = self.engine()?;

        if interleaved_coeffs.is_empty() {
            return Ok(EncodedMatrix {
                rows:    0,
                cols:    0,
                storage: EncodedMatrixStorage::Field(engine.empty_buffer::<GpuField>(0)),
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
        if total_size > u32::MAX as usize {
            return Err("GPU encode launch exceeds current 32-bit grid limit".into());
        }
        trace_event(format_args!(
            "encode rows={} codeword_length={} interleaving_depth={} message_length={} \
             polynomials={} path=direct",
            rows,
            codeword_length,
            interleaving_depth,
            message_length,
            interleaved_coeffs.len(),
        ));

        let pack_started = Instant::now();
        let mut packed = vec![GpuField::default(); total_size];
        for (poly_index, poly) in interleaved_coeffs.iter().enumerate() {
            for (block_index, block) in poly.chunks_exact(message_length).enumerate() {
                let row_start = (poly_index * interleaving_depth + block_index) * codeword_length;
                for (coeff_index, &coeff) in block.iter().enumerate() {
                    packed[row_start + coeff_index] = fr_to_gpu(coeff);
                }
            }
        }
        let pack_elapsed = pack_started.elapsed();

        let roots_started = Instant::now();
        let roots = engine.root_table(codeword_length)?;
        let roots_elapsed = roots_started.elapsed();

        let gpu_started = Instant::now();
        let current = engine.buffer_with_data(&packed);
        let stages = codeword_length.trailing_zeros() as usize;
        let row_len = codeword_length;
        let bit_reverse_config = BitReverseConfig {
            length: row_len as u32,
            log_n:  codeword_length.trailing_zeros(),
            _pad0:  0,
            _pad1:  0,
        };
        let bit_reverse_threads = engine.threads_per_threadgroup(&engine.bit_reverse, row_len);
        let row_butterflies = row_len / 2;
        let stage_threads = engine.threads_per_threadgroup(&engine.stage, row_butterflies);
        for row in 0..rows {
            let row_start = row * row_len;
            let row_offset = (row_start * size_of::<GpuField>()) as NSUInteger;
            let command_buffer = engine.queue.new_command_buffer();

            let bit_reverse_encoder = command_buffer.new_compute_command_encoder();
            bit_reverse_encoder.set_compute_pipeline_state(&engine.bit_reverse);
            bit_reverse_encoder.set_buffer(0, Some(&current), row_offset);
            bit_reverse_encoder.set_bytes(
                1,
                size_of::<BitReverseConfig>() as NSUInteger,
                (&bit_reverse_config as *const BitReverseConfig).cast::<c_void>(),
            );
            bit_reverse_encoder.dispatch_threads(
                MTLSize {
                    width:  row_len as u64,
                    height: 1,
                    depth:  1,
                },
                bit_reverse_threads,
            );
            bit_reverse_encoder.end_encoding();

            let stage_encoder = command_buffer.new_compute_command_encoder();
            stage_encoder.set_compute_pipeline_state(&engine.stage);
            stage_encoder.set_buffer(0, Some(&current), row_offset);
            stage_encoder.set_buffer(1, Some(&roots.buffer), 0);
            let mut twiddle_offset = 0usize;
            for stage in 0..stages {
                let half_m = 1usize << stage;
                let config = StageConfig {
                    half_m:         half_m as u32,
                    twiddle_offset: twiddle_offset as u32,
                    _pad0:          0,
                    _pad1:          0,
                };
                stage_encoder.set_bytes(
                    2,
                    size_of::<StageConfig>() as NSUInteger,
                    (&config as *const StageConfig).cast::<c_void>(),
                );
                stage_encoder.dispatch_threads(
                    MTLSize {
                        width:  row_butterflies as u64,
                        height: 1,
                        depth:  1,
                    },
                    stage_threads,
                );
                twiddle_offset += half_m;
            }
            stage_encoder.end_encoding();

            command_buffer.commit();
            command_buffer.wait_until_completed();
        }

        let transposed = engine.empty_buffer::<GpuField>(total_size);
        let transpose_params = TransposeParams {
            rows:           rows as u32,
            cols:           row_len as u32,
            total_elements: total_size as u32,
        };
        let transpose_threads = engine.threads_per_threadgroup(&engine.transpose, total_size);
        let command_buffer = engine.queue.new_command_buffer();
        let transpose_encoder = command_buffer.new_compute_command_encoder();
        transpose_encoder.set_compute_pipeline_state(&engine.transpose);
        transpose_encoder.set_buffer(0, Some(&current), 0);
        transpose_encoder.set_buffer(1, Some(&transposed), 0);
        transpose_encoder.set_bytes(
            2,
            size_of::<TransposeParams>() as NSUInteger,
            (&transpose_params as *const TransposeParams).cast::<c_void>(),
        );
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
            "encode timings codeword_length={} rows={} path=direct pack_us={} roots_us={} gpu_us={} \
             total_us={}",
            codeword_length,
            rows,
            pack_elapsed.as_micros(),
            roots_elapsed.as_micros(),
            gpu_elapsed.as_micros(),
            total_started.elapsed().as_micros()
        ));
        Ok(EncodedMatrix {
            rows:    codeword_length,
            cols:    rows,
            storage: EncodedMatrixStorage::Field(transposed),
        })
    }

    fn gpu_commit_artifact_with_path(
        &self,
        interleaved_coeffs: &[&[Fr]],
        codeword_length: usize,
        interleaving_depth: usize,
    ) -> Result<EncodedMatrix, String> {
        self.gpu_encode_artifact_with_path(interleaved_coeffs, codeword_length, interleaving_depth)
    }

    fn gpu_hash_rows(&self, matrix: &EncodedMatrix) -> Result<Vec<Hash>, String> {
        if matrix.rows == 0 {
            return Ok(Vec::new());
        }
        let engine = self.engine()?;
        let EncodedMatrixStorage::Field(buffer) = &matrix.storage;
        let total_elements = matrix.rows * matrix.cols;
        let total_bytes = total_elements * Fr::encoded_size();
        let message_size = matrix.cols * Fr::encoded_size();
        if total_elements > u32::MAX as usize || message_size > u32::MAX as usize {
            return Err("GPU hash launch exceeds current 32-bit grid limit".into());
        }

        let encoded = engine.empty_buffer::<u8>(total_bytes);
        let hashes = engine.empty_buffer::<Hash>(matrix.rows);
        let encode_params = FieldBytesParams {
            total_elements: total_elements as u32,
        };
        let hash_params = HashManyParams {
            size:  message_size as u32,
            count: matrix.rows as u32,
        };
        let command_buffer = engine.queue.new_command_buffer();
        let encode_encoder = command_buffer.new_compute_command_encoder();
        encode_encoder.set_compute_pipeline_state(&engine.encode_bytes);
        encode_encoder.set_buffer(0, Some(buffer), 0);
        encode_encoder.set_buffer(1, Some(&encoded), 0);
        encode_encoder.set_bytes(
            2,
            size_of::<FieldBytesParams>() as NSUInteger,
            (&encode_params as *const FieldBytesParams).cast::<c_void>(),
        );
        let encode_threads = engine.threads_per_threadgroup(&engine.encode_bytes, total_elements);
        encode_encoder.dispatch_threads(
            MTLSize {
                width:  total_elements as u64,
                height: 1,
                depth:  1,
            },
            encode_threads,
        );
        encode_encoder.end_encoding();

        let hash_encoder = command_buffer.new_compute_command_encoder();
        hash_encoder.set_compute_pipeline_state(&engine.sha256);
        hash_encoder.set_buffer(0, Some(&encoded), 0);
        hash_encoder.set_buffer(1, Some(&hashes), 0);
        hash_encoder.set_bytes(
            2,
            size_of::<HashManyParams>() as NSUInteger,
            (&hash_params as *const HashManyParams).cast::<c_void>(),
        );
        let hash_threads = engine.threads_per_threadgroup(&engine.sha256, matrix.rows);
        hash_encoder.dispatch_threads(
            MTLSize {
                width:  matrix.rows as u64,
                height: 1,
                depth:  1,
            },
            hash_threads,
        );
        hash_encoder.end_encoding();
        command_buffer.commit();
        command_buffer.wait_until_completed();

        let hash_started = Instant::now();
        let hashes = engine.read_buffer::<Hash>(&hashes, matrix.rows);
        trace_event(format_args!(
            "hash timings rows={} cols={} path=gpu-hash readback_us={} hash_us={}",
            matrix.rows,
            matrix.cols,
            0,
            hash_started.elapsed().as_micros(),
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
        let EncodedMatrixStorage::Field(buffer) = matrix.storage;
        let result: Vec<Fr> = self
            .engine()?
            .read_buffer::<GpuField>(&buffer, matrix.rows * matrix.cols)
            .into_iter()
            .map(gpu_to_fr)
            .collect();
        trace_event(format_args!(
            "readback timings codeword_length={} rows={} readback_us={}",
            codeword_length,
            matrix.rows,
            readback_started.elapsed().as_micros()
        ));
        Ok(result)
    }

    #[cfg(all(test, target_os = "macos"))]
    fn gpu_mul_pairs(&self, lhs: &[Fr], rhs: &[Fr]) -> Result<Vec<Fr>, String> {
        if lhs.len() != rhs.len() {
            return Err("lhs/rhs length mismatch".into());
        }

        let engine = self.engine()?;
        let count = lhs.len();
        if count == 0 {
            return Ok(Vec::new());
        }
        if count > u32::MAX as usize {
            return Err("GPU field multiplication launch exceeds current 32-bit grid limit".into());
        }

        let lhs_gpu: Vec<_> = lhs.iter().copied().map(fr_to_gpu).collect();
        let rhs_gpu: Vec<_> = rhs.iter().copied().map(fr_to_gpu).collect();
        let lhs_buffer = engine.buffer_with_data(&lhs_gpu);
        let rhs_buffer = engine.buffer_with_data(&rhs_gpu);
        let output = engine.empty_buffer::<GpuField>(count);

        let command_buffer = engine.queue.new_command_buffer();
        let encoder = command_buffer.new_compute_command_encoder();
        encoder.set_compute_pipeline_state(&engine.field_mul);
        encoder.set_buffer(0, Some(&lhs_buffer), 0);
        encoder.set_buffer(1, Some(&rhs_buffer), 0);
        encoder.set_buffer(2, Some(&output), 0);
        let params = FieldMulParams { count: count as u32 };
        encoder.set_bytes(
            3,
            size_of::<FieldMulParams>() as NSUInteger,
            (&params as *const FieldMulParams).cast::<c_void>(),
        );
        let threads = engine.threads_per_threadgroup(&engine.field_mul, count);
        encoder.dispatch_threads(
            MTLSize {
                width:  count as u64,
                height: 1,
                depth:  1,
            },
            threads,
        );
        encoder.end_encoding();
        command_buffer.commit();
        command_buffer.wait_until_completed();

        Ok(engine
            .read_buffer::<GpuField>(&output, count)
            .into_iter()
            .map(gpu_to_fr)
            .collect())
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

        let matrix = self.gpu_commit_artifact_with_path(
            interleaved_coeffs,
            codeword_length,
            interleaving_depth,
        )?;
        let leaf_hashes = self.gpu_hash_rows(&matrix)?;
        let EncodedMatrixStorage::Field(buffer) = matrix.storage;
        let rows = Arc::new(MetalMatrixRows {
            rows:    matrix.rows,
            cols:    matrix.cols,
            storage: MatrixStorage::Field(buffer),
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
            .field("storage", &"field")
            .finish()
    }
}

impl MatrixRows<Fr> for MetalMatrixRows {
    fn len(&self) -> usize {
        self.rows * self.cols
    }

    fn read_rows(&self, indices: &[usize]) -> Vec<Fr> {
        let mut out = Vec::with_capacity(indices.len() * self.cols);
        let MatrixStorage::Field(buffer) = &self.storage;
        let fields =
            unsafe { std::slice::from_raw_parts(buffer.contents().cast::<GpuField>(), self.len()) };
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
            let bit_reverse = library
                .get_function("bit_reverse_permute_in_place", None)
                .map_err(|err| err.to_string())
                .and_then(|function| device.new_compute_pipeline_state_with_function(&function))?;
            let stage = library
                .get_function("radix2_ntt_stage", None)
                .map_err(|err| err.to_string())
                .and_then(|function| device.new_compute_pipeline_state_with_function(&function))?;
            let field_mul = library
                .get_function("mul_field_elements", None)
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
                bit_reverse,
                stage,
                field_mul,
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
        let mut roots = Vec::with_capacity(codeword_length.saturating_sub(1));
        let stages = codeword_length.trailing_zeros() as usize;
        for stage in 0..stages {
            let m = 1usize << (stage + 1);
            let half_m = m >> 1;
            let stage_root = root.pow([(codeword_length / m) as u64]);
            let mut current = Fr::ONE;
            for _ in 0..half_m {
                roots.push(fr_to_gpu(current));
                current *= stage_root;
            }
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

fn gpu_geq_modulus(limbs: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if limbs[i] > GPU_FIELD_MODULUS[i] {
            return true;
        }
        if limbs[i] < GPU_FIELD_MODULUS[i] {
            return false;
        }
    }
    true
}

fn gpu_sub_modulus(limbs: &mut [u64; 4]) {
    let mut borrow = 0u64;
    for i in 0..4 {
        let (tmp, b1) = limbs[i].overflowing_sub(GPU_FIELD_MODULUS[i]);
        let (tmp, b2) = tmp.overflowing_sub(borrow);
        limbs[i] = tmp;
        borrow = (b1 as u64) | (b2 as u64);
    }
}

fn gpu_to_fr(mut value: GpuField) -> Fr {
    if gpu_geq_modulus(&value.limbs) {
        gpu_sub_modulus(&mut value.limbs);
    }
    Fp::<MontBackend<FrConfig, 4>, 4>(BigInt(value.limbs), PhantomData)
}

const SHADER_SOURCE: &str = r#"
#include <metal_stdlib>
using namespace metal;

struct Bn254Element {
    ulong limbs[4];
};

typedef Bn254Element Fe;

struct BitReverseConfig {
    uint length;
    uint log_n;
    uint _pad0;
    uint _pad1;
};

struct StageConfig {
    uint half_m;
    uint twiddle_offset;
    uint _pad0;
    uint _pad1;
};

struct PackParams {
    uint poly_size;
    uint row_len;
    uint interleaving_depth;
    uint message_length;
    uint coeff_bits;
    uint expansion_bits;
    uint total_elements;
};

struct TransposeParams {
    uint rows;
    uint cols;
    uint total_elements;
};

struct FieldBytesParams {
    uint total_elements;
};

struct HashManyParams {
    uint size;
    uint count;
};

struct FieldMulParams {
    uint count;
};

constant ulong BN254_MODULUS[4] = {
    0x43e1f593f0000001ul,
    0x2833e84879b97091ul,
    0xb85045b68181585dul,
    0x30644e72e131a029ul,
};

constant ulong MODULUS[4] = {
    0x43e1f593f0000001ul,
    0x2833e84879b97091ul,
    0xb85045b68181585dul,
    0x30644e72e131a029ul,
};

constant ulong BN254_N0PRIME = 0xc2e1f593effffffful;
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

inline Bn254Element make_element(ulong a0, ulong a1, ulong a2, ulong a3) {
    Bn254Element value;
    value.limbs[0] = a0;
    value.limbs[1] = a1;
    value.limbs[2] = a2;
    value.limbs[3] = a3;
    return value;
}

inline bool ge_modulus(Bn254Element value) {
    if (value.limbs[3] != BN254_MODULUS[3]) {
        return value.limbs[3] > BN254_MODULUS[3];
    }
    if (value.limbs[2] != BN254_MODULUS[2]) {
        return value.limbs[2] > BN254_MODULUS[2];
    }
    if (value.limbs[1] != BN254_MODULUS[1]) {
        return value.limbs[1] > BN254_MODULUS[1];
    }
    return value.limbs[0] >= BN254_MODULUS[0];
}

inline ulong add_with_carry(ulong a, ulong b, thread ulong &carry) {
    ulong sum = a + b;
    ulong c1 = sum < a ? 1ul : 0ul;
    ulong sum_with_carry = sum + carry;
    ulong c2 = sum_with_carry < sum ? 1ul : 0ul;
    carry = c1 + c2;
    return sum_with_carry;
}

inline ulong sub_with_borrow(ulong a, ulong b, thread ulong &borrow) {
    ulong diff = a - b;
    ulong b1 = diff > a ? 1ul : 0ul;
    ulong diff_with_borrow = diff - borrow;
    ulong b2 = diff_with_borrow > diff ? 1ul : 0ul;
    borrow = b1 | b2;
    return diff_with_borrow;
}

inline Bn254Element sub_modulus(Bn254Element value) {
    ulong borrow = 0;
    value.limbs[0] = sub_with_borrow(value.limbs[0], BN254_MODULUS[0], borrow);
    value.limbs[1] = sub_with_borrow(value.limbs[1], BN254_MODULUS[1], borrow);
    value.limbs[2] = sub_with_borrow(value.limbs[2], BN254_MODULUS[2], borrow);
    value.limbs[3] = sub_with_borrow(value.limbs[3], BN254_MODULUS[3], borrow);
    return value;
}

inline Bn254Element add_modulus(Bn254Element value) {
    ulong carry = 0;
    value.limbs[0] = add_with_carry(value.limbs[0], BN254_MODULUS[0], carry);
    value.limbs[1] = add_with_carry(value.limbs[1], BN254_MODULUS[1], carry);
    value.limbs[2] = add_with_carry(value.limbs[2], BN254_MODULUS[2], carry);
    value.limbs[3] = add_with_carry(value.limbs[3], BN254_MODULUS[3], carry);
    return value;
}

inline Bn254Element add_mod(Bn254Element lhs, Bn254Element rhs) {
    ulong carry = 0;
    Bn254Element result;
    result.limbs[0] = add_with_carry(lhs.limbs[0], rhs.limbs[0], carry);
    result.limbs[1] = add_with_carry(lhs.limbs[1], rhs.limbs[1], carry);
    result.limbs[2] = add_with_carry(lhs.limbs[2], rhs.limbs[2], carry);
    result.limbs[3] = add_with_carry(lhs.limbs[3], rhs.limbs[3], carry);

    if (carry != 0 || ge_modulus(result)) {
        result = sub_modulus(result);
    }

    return result;
}

inline Bn254Element sub_mod(Bn254Element lhs, Bn254Element rhs) {
    ulong borrow = 0;
    Bn254Element result;
    result.limbs[0] = sub_with_borrow(lhs.limbs[0], rhs.limbs[0], borrow);
    result.limbs[1] = sub_with_borrow(lhs.limbs[1], rhs.limbs[1], borrow);
    result.limbs[2] = sub_with_borrow(lhs.limbs[2], rhs.limbs[2], borrow);
    result.limbs[3] = sub_with_borrow(lhs.limbs[3], rhs.limbs[3], borrow);

    if (borrow != 0) {
        result = add_modulus(result);
    }

    return result;
}

inline void add_scaled_step(thread ulong &dst, ulong s, ulong a, thread ulong &carry) {
    ulong product_lo = s * a;
    ulong product_hi = mulhi(s, a);

    ulong sum = dst + product_lo;
    ulong carry0 = sum < dst ? 1ul : 0ul;
    ulong sum_with_carry = sum + carry;
    ulong carry1 = sum_with_carry < sum ? 1ul : 0ul;

    dst = sum_with_carry;
    carry = product_hi + carry0 + carry1;
}

inline void add_scaled(thread ulong *dst, ulong s, ulong a0, ulong a1, ulong a2, ulong a3) {
    ulong carry = 0;
    add_scaled_step(dst[0], s, a0, carry);
    add_scaled_step(dst[1], s, a1, carry);
    add_scaled_step(dst[2], s, a2, carry);
    add_scaled_step(dst[3], s, a3, carry);
    dst[4] += carry;
}

inline Bn254Element mont_mul(Bn254Element lhs, Bn254Element rhs) {
    ulong buf[9] = {0};
    uint off = 0;

    for (uint i = 0; i < 4; i++) {
        add_scaled(
            &buf[off],
            lhs.limbs[i],
            rhs.limbs[0],
            rhs.limbs[1],
            rhs.limbs[2],
            rhs.limbs[3]
        );

        ulong m = buf[off] * BN254_N0PRIME;
        add_scaled(
            &buf[off],
            m,
            BN254_MODULUS[0],
            BN254_MODULUS[1],
            BN254_MODULUS[2],
            BN254_MODULUS[3]
        );

        off += 1;
        buf[off + 4] = 0;
    }

    Bn254Element result = make_element(buf[off], buf[off + 1], buf[off + 2], buf[off + 3]);
    if (ge_modulus(result)) {
        result = sub_modulus(result);
    }
    return result;
}

inline uint reverse_low_bits(uint value, uint bits) {
    uint reversed = 0;
    for (uint i = 0; i < bits; i++) {
        reversed = (reversed << 1u) | (value & 1u);
        value >>= 1u;
    }
    return reversed;
}

inline Fe canonicalize(Fe value) {
    if (ge_modulus(value)) {
        return sub_modulus(value);
    }
    return value;
}

inline Fe from_mont(Fe value) {
    return canonicalize(mont_mul(value, FE_ONE));
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
    if (gid >= params.total_elements) {
        return;
    }

    uint row = gid / params.row_len;
    uint position = gid - row * params.row_len;
    uint expansion_mask = (1u << params.expansion_bits) - 1u;
    if ((position & expansion_mask) != 0) {
        Fe zero = {{0ul, 0ul, 0ul, 0ul}};
        output[gid] = zero;
        return;
    }

    uint poly_index = row / params.interleaving_depth;
    uint block_index = row - poly_index * params.interleaving_depth;
    uint packed_index = position >> params.expansion_bits;
    uint coeff_index = packed_index;
    uint src = poly_index * params.poly_size + block_index * params.message_length + coeff_index;
    output[gid] = coeffs[src];
}

[[kernel]]
void bit_reverse_permute_in_place(
    device Bn254Element *values [[buffer(0)]],
    constant BitReverseConfig &config [[buffer(1)]],
    uint index [[thread_position_in_grid]]
) {
    if (index >= config.length) {
        return;
    }

    uint reversed = reverse_low_bits(index, config.log_n);
    if (reversed > index) {
        Bn254Element tmp = values[index];
        values[index] = values[reversed];
        values[reversed] = tmp;
    }
}

[[kernel]]
void radix2_ntt_stage(
    device Bn254Element *values [[buffer(0)]],
    device const Bn254Element *twiddles [[buffer(1)]],
    constant StageConfig &config [[buffer(2)]],
    uint index [[thread_position_in_grid]]
) {
    uint half_m = config.half_m;
    uint pair_in_group = index % half_m;
    uint group = index / half_m;
    uint base = group * (half_m << 1u) + pair_in_group;
    uint mate = base + half_m;

    Bn254Element even = values[base];
    Bn254Element odd = values[mate];
    Bn254Element twiddle = twiddles[config.twiddle_offset + pair_in_group];
    Bn254Element t = mont_mul(twiddle, odd);

    values[base] = add_mod(even, t);
    values[mate] = sub_mod(even, t);
}

kernel void mul_field_elements(
    device const Fe* lhs [[buffer(0)]],
    device const Fe* rhs [[buffer(1)]],
    device Fe* output [[buffer(2)]],
    constant FieldMulParams& params [[buffer(3)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= params.count) {
        return;
    }

    output[gid] = mont_mul(lhs[gid], rhs[gid]);
}

kernel void transpose_matrix(
    device const Fe* input [[buffer(0)]],
    device Fe* output [[buffer(1)]],
    constant TransposeParams& params [[buffer(2)]],
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

kernel void encode_field_rows_le(
    device const Fe* input [[buffer(0)]],
    device uchar* output [[buffer(1)]],
    constant FieldBytesParams& params [[buffer(2)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= params.total_elements) {
        return;
    }

    Fe canonical = from_mont(input[gid]);
    uint byte_offset = gid * 32u;
    for (uint limb = 0; limb < 4; ++limb) {
        ulong value = canonical.limbs[limb];
        for (uint byte = 0; byte < 8; ++byte) {
            output[byte_offset + limb * 8u + byte] = uchar((value >> (byte * 8u)) & 0xfful);
        }
    }
}

kernel void sha256_many(
    device const uchar* input [[buffer(0)]],
    device uchar* output [[buffer(1)]],
    constant HashManyParams& params [[buffer(2)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= params.count) {
        return;
    }

    uint offset = gid * params.size;
    uint total_blocks = (params.size + 9u + 63u) / 64u;
    uint total_padded_len = total_blocks * 64u;
    uint bit_len = params.size * 8u;

    uint h0 = 0x6a09e667u;
    uint h1 = 0xbb67ae85u;
    uint h2 = 0x3c6ef372u;
    uint h3 = 0xa54ff53au;
    uint h4 = 0x510e527fu;
    uint h5 = 0x9b05688cu;
    uint h6 = 0x1f83d9abu;
    uint h7 = 0x5be0cd19u;

    for (uint block = 0; block < total_blocks; ++block) {
        uint w[64];

        for (uint i = 0; i < 16; ++i) {
            uint word = 0u;
            for (uint j = 0; j < 4; ++j) {
                uint idx = block * 64u + i * 4u + j;
                uchar byte = 0u;
                if (idx < params.size) {
                    byte = input[offset + idx];
                } else if (idx == params.size) {
                    byte = 0x80u;
                } else if (idx >= total_padded_len - 8u) {
                    uint shift = (total_padded_len - 1u - idx) * 8u;
                    byte = shift >= 32u ? 0u : uchar((bit_len >> shift) & 0xffu);
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

    device uchar* out = output + gid * 32u;
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
    fn metal_matches_cpu_for_small_codeword_case() {
        let gpu = MetalBn254Ntt::new().unwrap();
        let mut rng = ark_std::test_rng();
        let coeffs: Vec<_> = (0..32).map(|_| Fr::rand(&mut rng)).collect();
        let cpu = reference_interleaved_encode(&[&coeffs], 32, 2);
        let gpu = gpu.gpu_encode(&[&coeffs], 32, 2).unwrap();
        assert_eq!(cpu, gpu);
    }

    #[test]
    fn metal_field_mul_matches_cpu() {
        let gpu = MetalBn254Ntt::new().unwrap();
        let mut rng = ark_std::test_rng();
        let lhs: Vec<_> = (0..4096).map(|_| Fr::rand(&mut rng)).collect();
        let rhs: Vec<_> = (0..4096).map(|_| Fr::rand(&mut rng)).collect();
        let expected: Vec<_> = lhs
            .iter()
            .zip(&rhs)
            .map(|(&a, &b)| a * b)
            .collect();
        let actual = gpu.gpu_mul_pairs(&lhs, &rhs).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn metal_matches_cpu_for_multi_poly_case() {
        let gpu = MetalBn254Ntt::new().unwrap();
        let mut rng = ark_std::test_rng();
        let coeffs_a: Vec<_> = (0..32).map(|_| Fr::rand(&mut rng)).collect();
        let coeffs_b: Vec<_> = (0..32).map(|_| Fr::rand(&mut rng)).collect();
        let coeffs = [&coeffs_a[..], &coeffs_b[..]];
        let cpu = reference_interleaved_encode(&coeffs, 32, 2);
        let gpu = gpu.gpu_encode(&coeffs, 32, 2).unwrap();
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
