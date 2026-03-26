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
struct GpuRnsField {
    residues: [u32; 17],
}

const GPU_FIELD_MODULUS: [u64; 4] = [
    0x43e1f593f0000001,
    0x2833e84879b97091,
    0xb85045b68181585d,
    0x30644e72e131a029,
];

const GPU_N0_INV: u64 = 0xc2e1f593efffffff;

const GPU_TO_NATIVE_ENCODED: GpuField = GpuField {
    limbs: [
        0xc98a876714ad5b2d,
        0xabb57c6cca8d74c5,
        0x9cb04378ada6ba90,
        0x0bc6c6fc34d72348,
    ],
};

const GPU_FROM_NATIVE_ENCODED: GpuField = GpuField {
    limbs: [
        0x29abd0815c91d481,
        0x6b1fa3c5d1c03f5c,
        0x73d062569b987093,
        0x3058ad599a6e3109,
    ],
};

const GPU_RNS_CHANNELS_A: usize = 9;
const GPU_RNS_CHANNELS_B: usize = 8;
const GPU_RNS_CHANNELS: usize = GPU_RNS_CHANNELS_A + GPU_RNS_CHANNELS_B;

const GPU_RNS_MODULI_A: [u32; GPU_RNS_CHANNELS_A] = [
    4_294_967_291,
    4_294_967_279,
    4_294_967_231,
    4_294_967_197,
    4_294_967_189,
    4_294_967_161,
    4_294_967_143,
    4_294_967_111,
    4_294_967_087,
];

const GPU_RNS_MODULI_B: [u32; GPU_RNS_CHANNELS_B] = [
    4_294_967_029,
    4_294_966_997,
    4_294_966_981,
    4_294_966_943,
    4_294_966_927,
    4_294_966_909,
    4_294_966_877,
    4_294_966_829,
];

const GPU_RNS_POW64_1_A: [u32; GPU_RNS_CHANNELS_A] = [
    25, 289, 4_225, 9_801, 11_449, 18_225, 23_409, 34_225, 43_681,
];

const GPU_RNS_POW64_1_B: [u32; GPU_RNS_CHANNELS_B] = [
    71_289, 89_401, 99_225, 124_609, 136_161, 149_769, 175_561, 218_089,
];

const GPU_RNS_POW64_2_A: [u32; GPU_RNS_CHANNELS_A] = [
    625, 83_521, 17_850_625, 96_059_601, 131_079_601, 332_150_625, 547_981_281,
    1_171_350_625, 1_908_029_761,
];

const GPU_RNS_POW64_2_B: [u32; GPU_RNS_CHANNELS_B] = [
    787_154_492,
    3_697_571_804,
    1_255_666_663,
    2_642_502_052,
    1_359_950_213,
    955_918_816,
    756_896_582,
    318_176_802,
];

const GPU_RNS_POW64_3_A: [u32; GPU_RNS_CHANNELS_A] = [
    15_625, 24_137_569, 2_404_447_698, 882_333_258, 1_786_802_888, 1_836_410_776,
    2_921_917_931, 252_126_551, 811_667_006,
];

const GPU_RNS_POW64_3_B: [u32; GPU_RNS_CHANNELS_B] = [
    1_712_346_303,
    186_958_302,
    827_484_346,
    1_602_545_630,
    3_271_828_542,
    2_873_175_807,
    3_835_591_876,
    1_376_482_054,
];

const GPU_RNS_A_GARNER_INV: [[u32; GPU_RNS_CHANNELS_A]; GPU_RNS_CHANNELS_A] = [
    [
        0, 357_913_940, 3_507_556_572, 1_507_807_633, 547_397_779, 958_108_059, 3_743_586_226,
        2_600_841_195, 273_698_883,
    ],
    [
        0, 0, 89_478_484, 2_252_238_896, 2_911_033_317, 3_093_832_277, 1_042_161_145,
        2_479_832_201, 1_096_111_392,
    ],
    [
        0, 0, 0, 2_652_773_857, 3_170_094_830, 3_620_043_750, 2_781_967_354, 1_753_778_237,
        1_461_481_856,
    ],
    [
        0, 0, 0, 0, 1_610_612_696, 1_312_351_077, 3_738_212_143, 2_846_664_248, 4_177_831_621,
    ],
    [0, 0, 0, 0, 0, 460_175_053, 2_894_434_379, 3_689_266_621, 547_397_766],
    [0, 0, 0, 0, 0, 0, 2_624_702_143, 773_094_080, 3_540_445_842],
    [0, 0, 0, 0, 0, 0, 0, 1_207_959_500, 1_917_396_021],
    [0, 0, 0, 0, 0, 0, 0, 0, 178_956_962],
    [0; GPU_RNS_CHANNELS_A],
];

const GPU_RNS_A_PREFIX_LIMBS: [[u64; 5]; GPU_RNS_CHANNELS_A] = [
    [0x0000000000000001, 0, 0, 0, 0],
    [0x00000000fffffffbu64, 0, 0, 0, 0],
    [0xffffffea00000055u64, 0, 0, 0, 0],
    [0x000005eaffffea6bu64, 0x00000000ffffffa9u64, 0, 0, 0],
    [0xfffda08a0008589fu64, 0xffffff460000278fu64, 0, 0, 0],
    [0x01063ef0fc82f58bu64, 0x0000754dffed175au64, 0x00000000fffffedbu64, 0, 0],
    [0x7237c475d6f083b3u64, 0xffaf3b380afeee7au64, 0xfffffe5400010fd0u64, 0, 0],
    [
        0x939c19458a414a05u64,
        0x3b4489fbdfdb3d47u64,
        0x00020f9cff0cc74fu64,
        0x00000000fffffdbbu64,
        0,
    ],
    [
        0xde7306c416d18263u64,
        0x0b538642ce2cd08bu64,
        0xfd8f7edaeb0881bau64,
        0xfffffd020003b379u64,
        0,
    ],
];

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct StageParams {
    total_butterflies: u32,
    row_len:           u32,
    half_len:          u32,
    step:              u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct PackParams {
    poly_size:          u32,
    row_len:            u32,
    interleaving_depth: u32,
    message_length:     u32,
    coeff_bits:         u32,
    expansion_bits:     u32,
    total_elements:     u32,
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
struct ElementCountParams {
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
    buffer:     Buffer,
    rns_buffer: Buffer,
}

enum EncodedMatrixStorage {
    Field(Buffer),
    Rns {
        buffer:      Buffer,
        source_rows: usize,
        source_cols: usize,
    },
}

struct EncodedMatrix {
    rows:    usize,
    cols:    usize,
    storage: EncodedMatrixStorage,
}

#[derive(Clone)]
enum MatrixStorage {
    Field(Buffer),
    Rns {
        buffer:      Buffer,
        source_rows: usize,
        source_cols: usize,
    },
}

#[derive(Clone)]
struct MetalMatrixRows {
    rows:    usize,
    cols:    usize,
    storage: MatrixStorage,
}

struct MetalNttEngine {
    device:         Device,
    queue:          CommandQueue,
    pack:           ComputePipelineState,
    pack_rns:       ComputePipelineState,
    rns_to_field:   ComputePipelineState,
    stage:          ComputePipelineState,
    stage_rns:      ComputePipelineState,
    #[allow(dead_code)]
    field_mul:      ComputePipelineState,
    #[allow(dead_code)]
    field_mul_rns:  ComputePipelineState,
    transpose:      ComputePipelineState,
    encode_bytes:   ComputePipelineState,
    encode_bytes_rns: ComputePipelineState,
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

    fn use_experimental_rns() -> bool {
        env::var_os("PROVEKIT_METAL_NTT_EXPERIMENTAL_RNS").is_some()
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
        self.gpu_encode_artifact_with_path(
            interleaved_coeffs,
            codeword_length,
            interleaving_depth,
            Self::use_experimental_rns(),
        )
    }

    fn gpu_encode_artifact_with_path(
        &self,
        interleaved_coeffs: &[&[Fr]],
        codeword_length: usize,
        interleaving_depth: usize,
        use_rns: bool,
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
        let total_butterflies = total_size / 2;
        if total_size > u32::MAX as usize {
            return Err("GPU transpose launch exceeds current 32-bit grid limit".into());
        }
        if total_butterflies > u32::MAX as usize {
            return Err("GPU kernel launch exceeds current 32-bit grid limit".into());
        }
        trace_event(format_args!(
            "encode rows={} codeword_length={} interleaving_depth={} message_length={} \
             polynomials={} path={}",
            rows,
            codeword_length,
            interleaving_depth,
            message_length,
            interleaved_coeffs.len(),
            if use_rns { "rns" } else { "direct" }
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
        let mut current_rns = use_rns.then(|| engine.empty_buffer::<GpuRnsField>(total_size));
        let mut scratch_rns = use_rns.then(|| engine.empty_buffer::<GpuRnsField>(total_size));

        let gpu_started = Instant::now();
        let command_buffer = engine.queue.new_command_buffer();
        let pack_encoder = command_buffer.new_compute_command_encoder();
        pack_encoder.set_compute_pipeline_state(if use_rns { &engine.pack_rns } else { &engine.pack });
        let pack_params = PackParams {
            poly_size:          poly_size as u32,
            row_len:            codeword_length as u32,
            interleaving_depth: interleaving_depth as u32,
            message_length:     message_length as u32,
            coeff_bits:         message_length.trailing_zeros(),
            expansion_bits:     (codeword_length / message_length).trailing_zeros(),
            total_elements:     total_size as u32,
        };
        pack_encoder.set_buffer(0, Some(&coeffs), 0);
        if use_rns {
            pack_encoder.set_buffer(1, current_rns.as_ref().map(|buffer| buffer.as_ref()), 0);
        } else {
            pack_encoder.set_buffer(1, Some(&current), 0);
        }
        pack_encoder.set_bytes(
            2,
            size_of::<PackParams>() as NSUInteger,
            (&pack_params as *const PackParams).cast::<c_void>(),
        );
        let pack_threads =
            engine.threads_per_threadgroup(if use_rns { &engine.pack_rns } else { &engine.pack }, total_size);
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
        let stage_pipeline = if use_rns {
            &engine.stage_rns
        } else {
            &engine.stage
        };
        encoder.set_compute_pipeline_state(stage_pipeline);

        let stages = codeword_length.trailing_zeros() as usize;
        for stage in 0..stages {
            let len = 1usize << (stage + 1);
            let half = len / 2;
            let params = StageParams {
                total_butterflies: total_butterflies as u32,
                row_len:           codeword_length as u32,
                half_len:          half as u32,
                step:              (codeword_length / len) as u32,
            };

            if use_rns {
                encoder.set_buffer(0, current_rns.as_ref().map(|buffer| buffer.as_ref()), 0);
                encoder.set_buffer(1, scratch_rns.as_ref().map(|buffer| buffer.as_ref()), 0);
                encoder.set_buffer(2, Some(&roots.rns_buffer), 0);
                encoder.set_bytes(
                    3,
                    size_of::<StageParams>() as NSUInteger,
                    (&params as *const StageParams).cast::<c_void>(),
                );
            } else {
                encoder.set_buffer(0, Some(&current), 0);
                encoder.set_buffer(1, Some(&scratch), 0);
                encoder.set_buffer(2, Some(&roots.buffer), 0);
                encoder.set_bytes(
                    3,
                    size_of::<StageParams>() as NSUInteger,
                    (&params as *const StageParams).cast::<c_void>(),
                );
            }

            let threads_per_threadgroup =
                engine.threads_per_threadgroup(stage_pipeline, total_butterflies);
            encoder.dispatch_threads(
                MTLSize {
                    width:  total_butterflies as u64,
                    height: 1,
                    depth:  1,
                },
                threads_per_threadgroup,
            );

            std::mem::swap(&mut current, &mut scratch);
            if let (Some(current_rns), Some(scratch_rns)) =
                (current_rns.as_mut(), scratch_rns.as_mut())
            {
                std::mem::swap(current_rns, scratch_rns);
            }
        }

        encoder.end_encoding();
        if use_rns {
            let convert_encoder = command_buffer.new_compute_command_encoder();
            convert_encoder.set_compute_pipeline_state(&engine.rns_to_field);
            let convert_params = ElementCountParams {
                total_elements: total_size as u32,
            };
            convert_encoder.set_buffer(0, current_rns.as_ref().map(|buffer| buffer.as_ref()), 0);
            convert_encoder.set_buffer(1, Some(&current), 0);
            convert_encoder.set_bytes(
                2,
                size_of::<ElementCountParams>() as NSUInteger,
                (&convert_params as *const ElementCountParams).cast::<c_void>(),
            );
            let convert_threads = engine.threads_per_threadgroup(&engine.rns_to_field, total_size);
            convert_encoder.dispatch_threads(
                MTLSize {
                    width:  total_size as u64,
                    height: 1,
                    depth:  1,
                },
                convert_threads,
            );
            convert_encoder.end_encoding();
        }
        let transpose_encoder = command_buffer.new_compute_command_encoder();
        transpose_encoder.set_compute_pipeline_state(&engine.transpose);
        let transpose_params = TransposeParams {
            rows:           rows as u32,
            cols:           codeword_length as u32,
            total_elements: total_size as u32,
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
            "encode timings codeword_length={} rows={} path={} pack_us={} roots_us={} gpu_us={} \
             total_us={}",
            codeword_length,
            rows,
            if use_rns { "rns" } else { "direct" },
            pack_elapsed.as_micros(),
            roots_elapsed.as_micros(),
            gpu_elapsed.as_micros(),
            total_started.elapsed().as_micros()
        ));
        Ok(EncodedMatrix {
            rows:    codeword_length,
            cols:    rows,
            storage: EncodedMatrixStorage::Field(scratch),
        })
    }

    fn gpu_commit_artifact_with_path(
        &self,
        interleaved_coeffs: &[&[Fr]],
        codeword_length: usize,
        interleaving_depth: usize,
        use_rns: bool,
    ) -> Result<EncodedMatrix, String> {
        if !use_rns {
            return self.gpu_encode_artifact_with_path(
                interleaved_coeffs,
                codeword_length,
                interleaving_depth,
                false,
            );
        }

        let total_started = Instant::now();
        let engine = self.engine()?;

        if interleaved_coeffs.is_empty() {
            return Ok(EncodedMatrix {
                rows:    0,
                cols:    0,
                storage: EncodedMatrixStorage::Rns {
                    buffer:      engine.empty_buffer::<GpuRnsField>(0),
                    source_rows: 0,
                    source_cols: 0,
                },
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
            return Err("GPU launch exceeds current 32-bit grid limit".into());
        }
        if total_butterflies > u32::MAX as usize {
            return Err("GPU kernel launch exceeds current 32-bit grid limit".into());
        }
        trace_event(format_args!(
            "encode rows={} codeword_length={} interleaving_depth={} message_length={} \
             polynomials={} path=rns-commit",
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
        let mut current_rns = engine.empty_buffer::<GpuRnsField>(total_size);
        let mut scratch_rns = engine.empty_buffer::<GpuRnsField>(total_size);

        let gpu_started = Instant::now();
        let command_buffer = engine.queue.new_command_buffer();

        let pack_encoder = command_buffer.new_compute_command_encoder();
        pack_encoder.set_compute_pipeline_state(&engine.pack_rns);
        let pack_params = PackParams {
            poly_size:          poly_size as u32,
            row_len:            codeword_length as u32,
            interleaving_depth: interleaving_depth as u32,
            message_length:     message_length as u32,
            coeff_bits:         message_length.trailing_zeros(),
            expansion_bits:     (codeword_length / message_length).trailing_zeros(),
            total_elements:     total_size as u32,
        };
        pack_encoder.set_buffer(0, Some(&coeffs), 0);
        pack_encoder.set_buffer(1, Some(&current_rns), 0);
        pack_encoder.set_bytes(
            2,
            size_of::<PackParams>() as NSUInteger,
            (&pack_params as *const PackParams).cast::<c_void>(),
        );
        let pack_threads = engine.threads_per_threadgroup(&engine.pack_rns, total_size);
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
        encoder.set_compute_pipeline_state(&engine.stage_rns);
        let stages = codeword_length.trailing_zeros() as usize;
        for stage in 0..stages {
            let len = 1usize << (stage + 1);
            let half = len / 2;
            let params = StageParams {
                total_butterflies: total_butterflies as u32,
                row_len:           codeword_length as u32,
                half_len:          half as u32,
                step:              (codeword_length / len) as u32,
            };

            encoder.set_buffer(0, Some(&current_rns), 0);
            encoder.set_buffer(1, Some(&scratch_rns), 0);
            encoder.set_buffer(2, Some(&roots.rns_buffer), 0);
            encoder.set_bytes(
                3,
                size_of::<StageParams>() as NSUInteger,
                (&params as *const StageParams).cast::<c_void>(),
            );

            let threads_per_threadgroup =
                engine.threads_per_threadgroup(&engine.stage_rns, total_butterflies);
            encoder.dispatch_threads(
                MTLSize {
                    width:  total_butterflies as u64,
                    height: 1,
                    depth:  1,
                },
                threads_per_threadgroup,
            );
            std::mem::swap(&mut current_rns, &mut scratch_rns);
        }
        encoder.end_encoding();

        command_buffer.commit();
        command_buffer.wait_until_completed();
        let gpu_elapsed = gpu_started.elapsed();

        trace_event(format_args!(
            "encode timings codeword_length={} rows={} path=rns-commit pack_us={} roots_us={} \
             gpu_us={} total_us={}",
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
            storage: EncodedMatrixStorage::Rns {
                buffer:      current_rns,
                source_rows: rows,
                source_cols: codeword_length,
            },
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
            total_elements: total_elements as u32,
        };
        let hash_params = HashManyParams {
            size:  row_size as u32,
            count: matrix.rows as u32,
        };

        let gpu_started = Instant::now();
        let command_buffer = engine.queue.new_command_buffer();

        if total_elements > 0 {
            let encoder = command_buffer.new_compute_command_encoder();
            match &matrix.storage {
                EncodedMatrixStorage::Field(buffer) => {
                    encoder.set_compute_pipeline_state(&engine.encode_bytes);
                    encoder.set_buffer(0, Some(buffer), 0);
                    encoder.set_buffer(1, Some(&bytes_buffer), 0);
                    encoder.set_bytes(
                        2,
                        size_of::<FieldBytesParams>() as NSUInteger,
                        (&params as *const FieldBytesParams).cast::<c_void>(),
                    );
                    let threads =
                        engine.threads_per_threadgroup(&engine.encode_bytes, total_elements);
                    encoder.dispatch_threads(
                        MTLSize {
                            width:  total_elements as u64,
                            height: 1,
                            depth:  1,
                        },
                        threads,
                    );
                }
                EncodedMatrixStorage::Rns {
                    buffer,
                    source_rows,
                    source_cols,
                } => {
                    let transpose_params = TransposeParams {
                        rows:           *source_rows as u32,
                        cols:           *source_cols as u32,
                        total_elements: total_elements as u32,
                    };
                    encoder.set_compute_pipeline_state(&engine.encode_bytes_rns);
                    encoder.set_buffer(0, Some(buffer), 0);
                    encoder.set_buffer(1, Some(&bytes_buffer), 0);
                    encoder.set_bytes(
                        2,
                        size_of::<TransposeParams>() as NSUInteger,
                        (&transpose_params as *const TransposeParams).cast::<c_void>(),
                    );
                    let threads =
                        engine.threads_per_threadgroup(&engine.encode_bytes_rns, total_elements);
                    encoder.dispatch_threads(
                        MTLSize {
                            width:  total_elements as u64,
                            height: 1,
                            depth:  1,
                        },
                        threads,
                    );
                }
            }
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
        let result: Vec<Fr> = match matrix.storage {
            EncodedMatrixStorage::Field(buffer) => self
                .engine()?
                .read_buffer::<GpuField>(&buffer, matrix.rows * matrix.cols)
                .into_iter()
                .map(gpu_to_fr)
                .collect(),
            EncodedMatrixStorage::Rns {
                buffer,
                source_rows,
                source_cols,
            } => {
                let values = self
                    .engine()?
                    .read_buffer::<GpuRnsField>(&buffer, source_rows * source_cols);
                let mut out = Vec::with_capacity(matrix.rows * matrix.cols);
                for row in 0..matrix.rows {
                    for col in 0..matrix.cols {
                        out.push(gpu_rns_to_fr(values[col * source_cols + row]));
                    }
                }
                out
            }
        };
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
        self.gpu_mul_pairs_with_path(lhs, rhs, Self::use_experimental_rns())
    }

    #[cfg(all(test, target_os = "macos"))]
    fn gpu_mul_pairs_with_path(
        &self,
        lhs: &[Fr],
        rhs: &[Fr],
        use_rns: bool,
    ) -> Result<Vec<Fr>, String> {
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
        let field_mul_pipeline = if use_rns {
            &engine.field_mul_rns
        } else {
            &engine.field_mul
        };
        encoder.set_compute_pipeline_state(field_mul_pipeline);
        encoder.set_buffer(0, Some(&lhs_buffer), 0);
        encoder.set_buffer(1, Some(&rhs_buffer), 0);
        encoder.set_buffer(2, Some(&output), 0);
        let params = FieldMulParams { count: count as u32 };
        encoder.set_bytes(
            3,
            size_of::<FieldMulParams>() as NSUInteger,
            (&params as *const FieldMulParams).cast::<c_void>(),
        );
        let threads = engine.threads_per_threadgroup(field_mul_pipeline, count);
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
            Self::use_experimental_rns(),
        )?;
        let leaf_hashes = self.gpu_hash_rows(&matrix)?;
        let rows = Arc::new(MetalMatrixRows {
            rows:    matrix.rows,
            cols:    matrix.cols,
            storage: match matrix.storage {
                EncodedMatrixStorage::Field(buffer) => MatrixStorage::Field(buffer),
                EncodedMatrixStorage::Rns {
                    buffer,
                    source_rows,
                    source_cols,
                } => MatrixStorage::Rns {
                    buffer,
                    source_rows,
                    source_cols,
                },
            },
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
            .field(
                "storage",
                &match &self.storage {
                    MatrixStorage::Field(_) => "field",
                    MatrixStorage::Rns { .. } => "rns",
                },
            )
            .finish()
    }
}

impl MatrixRows<Fr> for MetalMatrixRows {
    fn len(&self) -> usize {
        self.rows * self.cols
    }

    fn read_rows(&self, indices: &[usize]) -> Vec<Fr> {
        let mut out = Vec::with_capacity(indices.len() * self.cols);
        match &self.storage {
            MatrixStorage::Field(buffer) => {
                let fields = unsafe {
                    std::slice::from_raw_parts(buffer.contents().cast::<GpuField>(), self.len())
                };
                for &row in indices {
                    assert!(row < self.rows, "row index out of bounds");
                    let start = row * self.cols;
                    let end = start + self.cols;
                    out.extend(fields[start..end].iter().copied().map(gpu_to_fr));
                }
            }
            MatrixStorage::Rns {
                buffer,
                source_rows,
                source_cols,
            } => {
                let fields = unsafe {
                    std::slice::from_raw_parts(
                        buffer.contents().cast::<GpuRnsField>(),
                        source_rows * source_cols,
                    )
                };
                for &row in indices {
                    assert!(row < self.rows, "row index out of bounds");
                    for col in 0..self.cols {
                        out.push(gpu_rns_to_fr(fields[col * source_cols + row]));
                    }
                }
            }
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
            let pack_rns = library
                .get_function("pack_coefficients_rns", None)
                .map_err(|err| err.to_string())
                .and_then(|function| device.new_compute_pipeline_state_with_function(&function))?;
            let rns_to_field = library
                .get_function("convert_rns_to_field", None)
                .map_err(|err| err.to_string())
                .and_then(|function| device.new_compute_pipeline_state_with_function(&function))?;
            let stage = library
                .get_function("stage_ntt", None)
                .map_err(|err| err.to_string())
                .and_then(|function| device.new_compute_pipeline_state_with_function(&function))?;
            let stage_rns = library
                .get_function("stage_ntt_rns", None)
                .map_err(|err| err.to_string())
                .and_then(|function| device.new_compute_pipeline_state_with_function(&function))?;
            let field_mul = library
                .get_function("mul_field_elements", None)
                .map_err(|err| err.to_string())
                .and_then(|function| device.new_compute_pipeline_state_with_function(&function))?;
            let field_mul_rns = library
                .get_function("mul_field_elements_rns", None)
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
            let encode_bytes_rns = library
                .get_function("encode_rns_rows_le", None)
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
                pack_rns,
                rns_to_field,
                stage,
                stage_rns,
                field_mul,
                field_mul_rns,
                transpose,
                encode_bytes,
                encode_bytes_rns,
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
        let mut roots_rns = Vec::with_capacity(codeword_length / 2);
        let mut current = Fr::ONE;
        for _ in 0..(codeword_length / 2) {
            let root_gpu = fr_to_gpu(current);
            roots.push(root_gpu);
            roots_rns.push(gpu_field_to_rns(root_gpu));
            current *= root;
        }

        let table = Arc::new(RootTable {
            buffer:     self.buffer_with_data(&roots),
            rns_buffer: self.buffer_with_data(&roots_rns),
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

fn gpu_mont_mul_raw(a: GpuField, b: GpuField) -> GpuField {
    let mut t = [0u64; 5];

    for i in 0..4 {
        let mut carry = 0u64;
        for j in 0..4 {
            let product = (a.limbs[j] as u128) * (b.limbs[i] as u128);
            let lo = product as u64;
            let hi = (product >> 64) as u64;

            let (sum, c1) = t[j].overflowing_add(lo);
            let (sum2, c2) = sum.overflowing_add(carry);
            t[j] = sum2;
            carry = hi.wrapping_add(c1 as u64).wrapping_add(c2 as u64);
        }
        t[4] = carry;

        let m = t[0].wrapping_mul(GPU_N0_INV);
        carry = 0;

        {
            let product = (m as u128) * (GPU_FIELD_MODULUS[0] as u128);
            let lo = product as u64;
            let hi = (product >> 64) as u64;
            let (sum, c1) = t[0].overflowing_add(lo);
            let (sum2, c2) = sum.overflowing_add(carry);
            let _ = sum2;
            carry = hi.wrapping_add(c1 as u64).wrapping_add(c2 as u64);
        }

        for j in 1..4 {
            let product = (m as u128) * (GPU_FIELD_MODULUS[j] as u128);
            let lo = product as u64;
            let hi = (product >> 64) as u64;

            let (sum, c1) = t[j].overflowing_add(lo);
            let (sum2, c2) = sum.overflowing_add(carry);
            t[j - 1] = sum2;
            carry = hi.wrapping_add(c1 as u64).wrapping_add(c2 as u64);
        }

        let (sum, c) = t[4].overflowing_add(carry);
        t[3] = sum;
        t[4] = c as u64;
    }

    GpuField {
        limbs: [t[0], t[1], t[2], t[3]],
    }
}

fn gpu_raw_native_to_rns(value: GpuField) -> GpuRnsField {
    let mut residues = [0u32; GPU_RNS_CHANNELS];
    for channel in 0..GPU_RNS_MODULI_A.len() {
        let modulus = GPU_RNS_MODULI_A[channel] as u128;
        let limb0 = (value.limbs[0] as u128) % modulus;
        let limb1 = ((value.limbs[1] as u128) % modulus) * (GPU_RNS_POW64_1_A[channel] as u128);
        let limb2 = ((value.limbs[2] as u128) % modulus) * (GPU_RNS_POW64_2_A[channel] as u128);
        let limb3 = ((value.limbs[3] as u128) % modulus) * (GPU_RNS_POW64_3_A[channel] as u128);
        residues[channel] = ((limb0 + limb1 + limb2 + limb3) % modulus) as u32;
    }
    for channel in 0..GPU_RNS_MODULI_B.len() {
        let modulus = GPU_RNS_MODULI_B[channel] as u128;
        let limb0 = (value.limbs[0] as u128) % modulus;
        let limb1 = ((value.limbs[1] as u128) % modulus) * (GPU_RNS_POW64_1_B[channel] as u128);
        let limb2 = ((value.limbs[2] as u128) % modulus) * (GPU_RNS_POW64_2_B[channel] as u128);
        let limb3 = ((value.limbs[3] as u128) % modulus) * (GPU_RNS_POW64_3_B[channel] as u128);
        residues[GPU_RNS_MODULI_A.len() + channel] =
            ((limb0 + limb1 + limb2 + limb3) % modulus) as u32;
    }

    GpuRnsField { residues }
}

fn gpu_field_to_rns(value: GpuField) -> GpuRnsField {
    gpu_raw_native_to_rns(gpu_mont_mul_raw(value, GPU_TO_NATIVE_ENCODED))
}

fn gpu_rns_to_fr(value: GpuRnsField) -> Fr {
    let mut coeffs = [0u32; GPU_RNS_CHANNELS_A];
    for i in 0..GPU_RNS_CHANNELS_A {
        let mut t = value.residues[i];
        for j in 0..i {
            let modulus = GPU_RNS_MODULI_A[i] as u64;
            let delta = if t >= coeffs[j] {
                (t - coeffs[j]) as u64
            } else {
                (t as u64) + modulus - (coeffs[j] as u64)
            };
            t = ((delta * (GPU_RNS_A_GARNER_INV[j][i] as u64)) % modulus) as u32;
        }
        coeffs[i] = t;
    }

    let mut acc = [0u64; 6];
    for (channel, &coeff) in coeffs.iter().enumerate() {
        let scale = coeff as u128;
        let mut carry = 0u64;
        for limb in 0..5 {
            let product = (GPU_RNS_A_PREFIX_LIMBS[channel][limb] as u128) * scale;
            let lo = product as u64;
            let hi = (product >> 64) as u64;

            let (sum, c1) = acc[limb].overflowing_add(lo);
            let (sum2, c2) = sum.overflowing_add(carry);
            acc[limb] = sum2;
            carry = hi.wrapping_add(c1 as u64).wrapping_add(c2 as u64);
        }

        let mut idx = 5usize;
        while carry != 0 && idx < acc.len() {
            let (sum, overflow) = acc[idx].overflowing_add(carry);
            acc[idx] = sum;
            carry = overflow as u64;
            idx += 1;
        }
    }

    while acc[5] != 0 || acc[4] != 0 || gpu_geq_modulus(&[acc[0], acc[1], acc[2], acc[3]]) {
        let mut borrow = 0u64;
        for (limb, modulus) in GPU_FIELD_MODULUS.iter().enumerate() {
            let (tmp, b1) = acc[limb].overflowing_sub(*modulus);
            let (tmp, b2) = tmp.overflowing_sub(borrow);
            acc[limb] = tmp;
            borrow = (b1 as u64) | (b2 as u64);
        }
        for limb in 4..acc.len() {
            let (tmp, overflow) = acc[limb].overflowing_sub(borrow);
            acc[limb] = tmp;
            borrow = overflow as u64;
        }
    }

    gpu_to_fr(gpu_mont_mul_raw(
        GpuField {
            limbs: [acc[0], acc[1], acc[2], acc[3]],
        },
        GPU_FROM_NATIVE_ENCODED,
    ))
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

struct Fe {
    ulong limbs[4];
};

struct RnsFe {
    uint residues[17];
};

struct WideU32 {
    uint lo;
    uint hi;
};

struct U512 {
    ulong limbs[8];
};

struct StageParams {
    uint total_butterflies;
    uint row_len;
    uint half_len;
    uint step;
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

struct ElementCountParams {
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

constant ulong MODULUS[4] = {
    0x43e1f593f0000001ul,
    0x2833e84879b97091ul,
    0xb85045b68181585dul,
    0x30644e72e131a029ul
};

constant ulong MODULUS_X2[4] = {
    0x87c3eb27e0000002ul,
    0x5067d090f372e122ul,
    0x70a08b6d0302b0baul,
    0x60c89ce5c2634053ul
};

constant ulong N0_INV = 0xc2e1f593effffffful;
constant Fe FE_ONE = {{1ul, 0ul, 0ul, 0ul}};
constant Fe TO_NATIVE_ENCODED = {{
    0xc98a876714ad5b2dul,
    0xabb57c6cca8d74c5ul,
    0x9cb04378ada6ba90ul,
    0x0bc6c6fc34d72348ul
}};

constant Fe FROM_NATIVE_ENCODED = {{
    0x29abd0815c91d481ul,
    0x6b1fa3c5d1c03f5cul,
    0x73d062569b987093ul,
    0x3058ad599a6e3109ul
}};

constant uint RNS_MODULI_A[9] = {
    4294967291u, 4294967279u, 4294967231u, 4294967197u, 4294967189u,
    4294967161u, 4294967143u, 4294967111u, 4294967087u
};

constant uint RNS_MODULI_B[8] = {
    4294967029u, 4294966997u, 4294966981u, 4294966943u,
    4294966927u, 4294966909u, 4294966877u, 4294966829u
};

constant uint RNS_DELTAS_A[9] = {
    5u, 17u, 65u, 99u, 107u, 135u, 153u, 185u, 209u
};

constant uint RNS_DELTAS_B[8] = {
    267u, 299u, 315u, 353u, 369u, 387u, 419u, 467u
};

constant uint RNS_POW64_1_A[9] = {
    25u, 289u, 4225u, 9801u, 11449u, 18225u, 23409u, 34225u, 43681u
};

constant uint RNS_POW64_1_B[8] = {
    71289u, 89401u, 99225u, 124609u, 136161u, 149769u, 175561u, 218089u
};

constant uint RNS_POW64_2_A[9] = {
    625u, 83521u, 17850625u, 96059601u, 131079601u, 332150625u, 547981281u,
    1171350625u, 1908029761u
};

constant uint RNS_POW64_2_B[8] = {
    787154492u, 3697571804u, 1255666663u, 2642502052u,
    1359950213u, 955918816u, 756896582u, 318176802u
};

constant uint RNS_POW64_3_A[9] = {
    15625u, 24137569u, 2404447698u, 882333258u, 1786802888u,
    1836410776u, 2921917931u, 252126551u, 811667006u
};

constant uint RNS_POW64_3_B[8] = {
    1712346303u, 186958302u, 827484346u, 1602545630u,
    3271828542u, 2873175807u, 3835591876u, 1376482054u
};

constant uint RNS_TWO_P_A[9] = {
    1125683747u, 415702855u, 943213288u, 826223898u, 897781823u,
    2760966300u, 601187501u, 1125777576u, 2734870098u
};

constant uint RNS_TWO_P_B[8] = {
    2868295129u, 3248957243u, 1280228838u, 2074810309u,
    310065391u, 1348492001u, 3418765132u, 1439800796u
};

constant uint RNS_NEG_P_INV_A[9] = {
    205600050u, 1330362898u, 1847816289u, 3724558789u, 972238307u,
    2666190081u, 1991163260u, 4252897074u, 2800423899u
};

constant uint RNS_P_MOD_B[8] = {
    3581631079u, 3771962120u, 640114419u, 3184888626u,
    2302516159u, 2821729455u, 1709382566u, 719900398u
};

constant uint RNS_MA_INV_B[8] = {
    822361013u, 1236180186u, 3033096522u, 175772267u,
    3543608642u, 3542454028u, 283242363u, 2089808385u
};

constant uint RNS_A_GARNER_INV[9][9] = {
    {0u, 357913940u, 3507556572u, 1507807633u, 547397779u, 958108059u, 3743586226u, 2600841195u, 273698883u},
    {0u, 0u, 89478484u, 2252238896u, 2911033317u, 3093832277u, 1042161145u, 2479832201u, 1096111392u},
    {0u, 0u, 0u, 2652773857u, 3170094830u, 3620043750u, 2781967354u, 1753778237u, 1461481856u},
    {0u, 0u, 0u, 0u, 1610612696u, 1312351077u, 3738212143u, 2846664248u, 4177831621u},
    {0u, 0u, 0u, 0u, 0u, 460175053u, 2894434379u, 3689266621u, 547397766u},
    {0u, 0u, 0u, 0u, 0u, 0u, 2624702143u, 773094080u, 3540445842u},
    {0u, 0u, 0u, 0u, 0u, 0u, 0u, 1207959500u, 1917396021u},
    {0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 178956962u},
    {0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u}
};

constant uint RNS_B_GARNER_INV[8][8] = {
    {0u, 402653156u, 3131746757u, 2447132328u, 2736988728u, 393705300u, 2571328854u, 2813203273u},
    {0u, 0u, 805306309u, 2465629171u, 3497330212u, 1317773938u, 2398023173u, 1099306986u},
    {0u, 0u, 0u, 2599585255u, 3738211955u, 656175500u, 2766949815u, 2797379711u},
    {0u, 0u, 0u, 0u, 268435433u, 3410709016u, 455526790u, 2298184005u},
    {0u, 0u, 0u, 0u, 0u, 2624702000u, 3178275489u, 657392882u},
    {0u, 0u, 0u, 0u, 0u, 0u, 1476394864u, 590557939u},
    {0u, 0u, 0u, 0u, 0u, 0u, 0u, 3847574451u},
    {0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u}
};

constant uint RNS_A_PREFIX_B[9][8] = {
    {1u, 1u, 1u, 1u, 1u, 1u, 1u, 1u},
    {262u, 294u, 310u, 348u, 364u, 382u, 414u, 462u},
    {65500u, 82908u, 92380u, 116928u, 128128u, 141340u, 166428u, 207900u},
    {13231000u, 19400472u, 23095000u, 33675264u, 38950912u, 45511480u, 58915512u, 83575800u},
    {2222808000u, 3880094400u, 693553019u, 4258550113u, 1926812386u, 222405513u, 1673096332u, 691126597u},
    {3461983622u, 1948834319u, 2525117579u, 3926360649u, 2313714673u, 2144006914u, 2315063467u, 3992465667u},
    {1715333030u, 1781270538u, 3549631215u, 1248199825u, 243400680u, 3418878703u, 348092447u, 2648818112u},
    {2274449115u, 2367478728u, 3809648357u, 531882306u, 1034943756u, 1153771428u, 2398286485u, 2800289171u},
    {1821245183u, 3604621178u, 1333083595u, 3456888548u, 1451106316u, 1133615370u, 2853343480u, 3702616515u}
};

constant uint RNS_B_PREFIX_A[8][9] = {
    {1u, 1u, 1u, 1u, 1u, 1u, 1u, 1u, 1u},
    {4294967029u, 4294967029u, 4294967029u, 4294967029u, 4294967029u, 4294967029u, 4294967029u, 4294967029u, 4294967029u},
    {77028u, 70500u, 47268u, 33600u, 30720u, 21648u, 16644u, 9348u, 5220u},
    {4271088611u, 4273958279u, 4283150231u, 4287709597u, 4288577429u, 4291070521u, 4292270815u, 4293751871u, 4294413767u},
    {4014813349u, 2764056721u, 3403296000u, 1843430400u, 1571880960u, 849467520u, 539265600u, 204160320u, 79678080u},
    {3191787195u, 2009606541u, 485118671u, 489986852u, 484038624u, 3088056887u, 3777710404u, 1089205119u, 136408461u},
    {508002154u, 3769886376u, 2705575485u, 617704125u, 1908135328u, 3493687778u, 778996922u, 3318855734u, 1489096464u},
    {140505503u, 629126335u, 3970823u, 4198138259u, 1662216935u, 4225052400u, 3240208755u, 776805335u, 822339911u}
};

constant ulong RNS_A_PREFIX_LIMBS[9][5] = {
    {0x0000000000000001ul, 0x0000000000000000ul, 0x0000000000000000ul, 0x0000000000000000ul, 0x0000000000000000ul},
    {0x00000000fffffffbul, 0x0000000000000000ul, 0x0000000000000000ul, 0x0000000000000000ul, 0x0000000000000000ul},
    {0xffffffea00000055ul, 0x0000000000000000ul, 0x0000000000000000ul, 0x0000000000000000ul, 0x0000000000000000ul},
    {0x000005eaffffea6bul, 0x00000000ffffffa9ul, 0x0000000000000000ul, 0x0000000000000000ul, 0x0000000000000000ul},
    {0xfffda08a0008589ful, 0xffffff460000278ful, 0x0000000000000000ul, 0x0000000000000000ul, 0x0000000000000000ul},
    {0x01063ef0fc82f58bul, 0x0000754dffed175aul, 0x00000000fffffedbul, 0x0000000000000000ul, 0x0000000000000000ul},
    {0x7237c475d6f083b3ul, 0xffaf3b380afeee7aul, 0xfffffe5400010fd0ul, 0x0000000000000000ul, 0x0000000000000000ul},
    {0x939c19458a414a05ul, 0x3b4489fbdfdb3d47ul, 0x00020f9cff0cc74ful, 0x00000000fffffdbbul, 0x0000000000000000ul},
    {0xde7306c416d18263ul, 0x0b538642ce2cd08bul, 0xfd8f7edaeb0881baul, 0xfffffd020003b379ul, 0x0000000000000000ul}
};

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

inline bool geq_mod_x2(Fe a) {
    for (int i = 3; i >= 0; --i) {
        if (a.limbs[i] > MODULUS_X2[i]) {
            return true;
        }
        if (a.limbs[i] < MODULUS_X2[i]) {
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

inline Fe sub_modulus_x2(Fe a) {
    Fe out;
    ulong borrow = 0;
    for (uint i = 0; i < 4; ++i) {
        ulong tmp = a.limbs[i] - MODULUS_X2[i] - borrow;
        borrow = (a.limbs[i] < MODULUS_X2[i] + borrow) ? 1ul : 0ul;
        out.limbs[i] = tmp;
    }
    return out;
}

inline ulong add_mod_with_flag(Fe a, Fe b, thread Fe* out) {
    Fe sum;
    ulong carry = 0;
    for (uint i = 0; i < 4; ++i) {
        ulong limb_sum = a.limbs[i] + b.limbs[i];
        ulong c1 = limb_sum < a.limbs[i] ? 1ul : 0ul;
        ulong sum2 = limb_sum + carry;
        ulong c2 = sum2 < limb_sum ? 1ul : 0ul;
        sum.limbs[i] = sum2;
        carry = c1 + c2;
    }
    ulong reduced = geq_mod_x2(sum) ? 1ul : 0ul;
    if (reduced != 0ul) {
        sum = sub_modulus_x2(sum);
    }
    *out = sum;
    return reduced;
}

inline ulong sub_mod_with_flag(Fe a, Fe b, thread Fe* out) {
    Fe diff;
    ulong borrow = 0;
    for (uint i = 0; i < 4; ++i) {
        ulong tmp = a.limbs[i] - b.limbs[i] - borrow;
        ulong next_borrow = (a.limbs[i] < b.limbs[i] + borrow) ? 1ul : 0ul;
        diff.limbs[i] = tmp;
        borrow = next_borrow;
    }
    if (borrow != 0) {
        ulong carry = 0;
        for (uint i = 0; i < 4; ++i) {
            ulong sum = diff.limbs[i] + MODULUS_X2[i];
            ulong c1 = sum < diff.limbs[i] ? 1ul : 0ul;
            ulong sum2 = sum + carry;
            ulong c2 = sum2 < sum ? 1ul : 0ul;
            diff.limbs[i] = sum2;
            carry = c1 + c2;
        }
    }
    *out = diff;
    return borrow;
}

inline Fe add_mod(Fe a, Fe b) {
    Fe out;
    add_mod_with_flag(a, b, &out);
    return out;
}

inline Fe sub_mod(Fe a, Fe b) {
    Fe out;
    sub_mod_with_flag(a, b, &out);
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
    return out;
}

inline Fe canonicalize(Fe a) {
    if (geq_mod(a)) {
        return sub_modulus(a);
    }
    return a;
}

inline Fe from_mont(Fe a) {
    return canonicalize(mont_mul(a, FE_ONE));
}

// Keep the RNS hot path on 32-bit arithmetic; Metal can still expose the high half directly.
inline WideU32 mul_wide_u32(uint a, uint b) {
    WideU32 out;
    out.lo = a * b;
    out.hi = mulhi(a, b);
    return out;
}

inline WideU32 fold_pseudo_mersenne_u32(uint lo, uint hi, uint delta) {
    WideU32 scaled = mul_wide_u32(hi, delta);
    WideU32 out;
    out.lo = lo + scaled.lo;
    out.hi = scaled.hi + ((out.lo < lo) ? 1u : 0u);
    return out;
}

inline uint rns_reduce_wide_u32(WideU32 value, uint modulus, uint delta) {
    WideU32 reduced = fold_pseudo_mersenne_u32(value.lo, value.hi, delta);
    reduced = fold_pseudo_mersenne_u32(reduced.lo, reduced.hi, delta);
    reduced = fold_pseudo_mersenne_u32(reduced.lo, reduced.hi, delta);

    uint out = reduced.lo + reduced.hi * delta;
    if (out >= modulus) {
        out -= modulus;
    }
    return out;
}

inline uint rns_reduce_u64_boundary(ulong x, uint modulus, uint delta) {
    ulong folded = (ulong)((uint)x) + ((x >> 32) * (ulong)delta);
    ulong reduced = (ulong)((uint)folded) + ((folded >> 32) * (ulong)delta);
    if (reduced >= (ulong)modulus) {
        reduced -= (ulong)modulus;
    }
    return (uint)reduced;
}

inline uint rns_add_mod(uint a, uint b, uint modulus) {
    uint sum = a + b;
    if (sum < a) {
        return sum + (0u - modulus);
    }
    if (sum >= modulus) {
        sum -= modulus;
    }
    return sum;
}

inline uint rns_sub_mod(uint a, uint b, uint modulus) {
    uint diff = a - b;
    if (a < b) {
        diff -= (0u - modulus);
    }
    return diff;
}

inline uint rns_mul_mod(uint a, uint b, uint modulus, uint delta) {
    return rns_reduce_wide_u32(mul_wide_u32(a, b), modulus, delta);
}

inline uint raw_to_residue(
    Fe value,
    uint modulus,
    uint delta,
    uint pow64_1,
    uint pow64_2,
    uint pow64_3
) {
    uint acc = rns_reduce_u64_boundary(value.limbs[0], modulus, delta);
    uint limb1 = rns_mul_mod(
        rns_reduce_u64_boundary(value.limbs[1], modulus, delta),
        pow64_1,
        modulus,
        delta
    );
    uint limb2 = rns_mul_mod(
        rns_reduce_u64_boundary(value.limbs[2], modulus, delta),
        pow64_2,
        modulus,
        delta
    );
    uint limb3 = rns_mul_mod(
        rns_reduce_u64_boundary(value.limbs[3], modulus, delta),
        pow64_3,
        modulus,
        delta
    );
    acc = rns_add_mod(acc, limb1, modulus);
    acc = rns_add_mod(acc, limb2, modulus);
    acc = rns_add_mod(acc, limb3, modulus);
    return acc;
}

inline RnsFe raw_to_rns(Fe value) {
    RnsFe out;
    for (uint i = 0; i < 9; ++i) {
        out.residues[i] = raw_to_residue(
            value,
            RNS_MODULI_A[i],
            RNS_DELTAS_A[i],
            RNS_POW64_1_A[i],
            RNS_POW64_2_A[i],
            RNS_POW64_3_A[i]
        );
    }
    for (uint i = 0; i < 8; ++i) {
        out.residues[9u + i] = raw_to_residue(
            value,
            RNS_MODULI_B[i],
            RNS_DELTAS_B[i],
            RNS_POW64_1_B[i],
            RNS_POW64_2_B[i],
            RNS_POW64_3_B[i]
        );
    }
    return out;
}

inline RnsFe to_native_rns(Fe value) {
    return raw_to_rns(mont_mul(value, TO_NATIVE_ENCODED));
}

inline RnsFe rns_add(RnsFe a, RnsFe b) {
    RnsFe out;
    for (uint i = 0; i < 9; ++i) {
        out.residues[i] = rns_add_mod(a.residues[i], b.residues[i], RNS_MODULI_A[i]);
    }
    for (uint i = 0; i < 8; ++i) {
        out.residues[9u + i] = rns_add_mod(
            a.residues[9u + i],
            b.residues[9u + i],
            RNS_MODULI_B[i]
        );
    }
    return out;
}

inline RnsFe rns_sub(RnsFe a, RnsFe b) {
    RnsFe out;
    for (uint i = 0; i < 9; ++i) {
        out.residues[i] = rns_sub_mod(a.residues[i], b.residues[i], RNS_MODULI_A[i]);
    }
    for (uint i = 0; i < 8; ++i) {
        out.residues[9u + i] = rns_sub_mod(
            a.residues[9u + i],
            b.residues[9u + i],
            RNS_MODULI_B[i]
        );
    }
    return out;
}

inline RnsFe rns_add_two_p(RnsFe value) {
    for (uint i = 0; i < 9; ++i) {
        value.residues[i] = rns_add_mod(value.residues[i], RNS_TWO_P_A[i], RNS_MODULI_A[i]);
    }
    for (uint i = 0; i < 8; ++i) {
        value.residues[9u + i] = rns_add_mod(
            value.residues[9u + i],
            RNS_TWO_P_B[i],
            RNS_MODULI_B[i]
        );
    }
    return value;
}

inline void add_carry_limb_6(thread ulong acc[6], uint start, ulong carry) {
    uint idx = start;
    while (carry != 0ul && idx < 6u) {
        ulong sum = acc[idx] + carry;
        carry = (sum < acc[idx]) ? 1ul : 0ul;
        acc[idx] = sum;
        idx += 1u;
    }
}

inline void base_extend_a_to_b(thread const uint src[9], thread uint dst[8]) {
    uint coeffs[9];
    for (uint i = 0; i < 9; ++i) {
        uint t = src[i];
        for (uint j = 0; j < i; ++j) {
            t = rns_mul_mod(
                rns_sub_mod(t, coeffs[j], RNS_MODULI_A[i]),
                RNS_A_GARNER_INV[j][i],
                RNS_MODULI_A[i],
                RNS_DELTAS_A[i]
            );
        }
        coeffs[i] = t;
    }

    for (uint target = 0; target < 8; ++target) {
        uint acc = 0u;
        for (uint i = 0; i < 9; ++i) {
            uint scaled = rns_mul_mod(
                coeffs[i],
                RNS_A_PREFIX_B[i][target],
                RNS_MODULI_B[target],
                RNS_DELTAS_B[target]
            );
            acc = rns_add_mod(acc, scaled, RNS_MODULI_B[target]);
        }
        dst[target] = acc;
    }
}

inline void base_extend_b_to_a(thread const uint src[8], thread uint dst[9]) {
    uint coeffs[8];
    for (uint i = 0; i < 8; ++i) {
        uint t = src[i];
        for (uint j = 0; j < i; ++j) {
            t = rns_mul_mod(
                rns_sub_mod(t, coeffs[j], RNS_MODULI_B[i]),
                RNS_B_GARNER_INV[j][i],
                RNS_MODULI_B[i],
                RNS_DELTAS_B[i]
            );
        }
        coeffs[i] = t;
    }

    for (uint target = 0; target < 9; ++target) {
        uint acc = 0u;
        for (uint i = 0; i < 8; ++i) {
            uint scaled = rns_mul_mod(
                coeffs[i],
                RNS_B_PREFIX_A[i][target],
                RNS_MODULI_A[target],
                RNS_DELTAS_A[target]
            );
            acc = rns_add_mod(acc, scaled, RNS_MODULI_A[target]);
        }
        dst[target] = acc;
    }
}

inline RnsFe rns_native_mont_mul(RnsFe a, RnsFe b) {
    uint q_a[9];
    for (uint i = 0; i < 9; ++i) {
        uint t_a = rns_mul_mod(
            a.residues[i],
            b.residues[i],
            RNS_MODULI_A[i],
            RNS_DELTAS_A[i]
        );
        q_a[i] = rns_mul_mod(
            t_a,
            RNS_NEG_P_INV_A[i],
            RNS_MODULI_A[i],
            RNS_DELTAS_A[i]
        );
    }

    uint q_b[8];
    base_extend_a_to_b(q_a, q_b);

    uint u_b[8];
    for (uint i = 0; i < 8; ++i) {
        uint t_b = rns_mul_mod(
            a.residues[9u + i],
            b.residues[9u + i],
            RNS_MODULI_B[i],
            RNS_DELTAS_B[i]
        );
        uint qp = rns_mul_mod(
            q_b[i],
            RNS_P_MOD_B[i],
            RNS_MODULI_B[i],
            RNS_DELTAS_B[i]
        );
        uint numerator = rns_add_mod(t_b, qp, RNS_MODULI_B[i]);
        u_b[i] = rns_mul_mod(
            numerator,
            RNS_MA_INV_B[i],
            RNS_MODULI_B[i],
            RNS_DELTAS_B[i]
        );
    }

    uint u_a[9];
    base_extend_b_to_a(u_b, u_a);

    RnsFe out;
    for (uint i = 0; i < 9; ++i) {
        out.residues[i] = u_a[i];
    }
    for (uint i = 0; i < 8; ++i) {
        out.residues[9u + i] = u_b[i];
    }
    return out;
}

inline void reconstruct_a_raw(RnsFe value, thread ulong acc[6]) {
    uint coeffs[9];
    for (uint i = 0; i < 9; ++i) {
        uint t = value.residues[i];
        for (uint j = 0; j < i; ++j) {
            t = rns_mul_mod(
                rns_sub_mod(t, coeffs[j], RNS_MODULI_A[i]),
                RNS_A_GARNER_INV[j][i],
                RNS_MODULI_A[i],
                RNS_DELTAS_A[i]
            );
        }
        coeffs[i] = t;
    }

    for (uint i = 0; i < 6; ++i) {
        acc[i] = 0ul;
    }

    for (uint channel = 0; channel < 9; ++channel) {
        ulong carry = 0ul;
        ulong scale = (ulong)coeffs[channel];
        for (uint limb = 0; limb < 5; ++limb) {
            ulong lo = RNS_A_PREFIX_LIMBS[channel][limb] * scale;
            ulong hi = mulhi(RNS_A_PREFIX_LIMBS[channel][limb], scale);

            ulong sum = acc[limb] + lo;
            ulong c1 = (sum < acc[limb]) ? 1ul : 0ul;
            ulong sum2 = sum + carry;
            ulong c2 = (sum2 < sum) ? 1ul : 0ul;
            acc[limb] = sum2;
            carry = hi + c1 + c2;
        }
        add_carry_limb_6(acc, 5u, carry);
    }
}

inline bool geq_mod_u384(thread const ulong value[6]) {
    if (value[5] != 0ul || value[4] != 0ul) {
        return true;
    }
    for (int i = 3; i >= 0; --i) {
        if (value[i] > MODULUS[i]) {
            return true;
        }
        if (value[i] < MODULUS[i]) {
            return false;
        }
    }
    return true;
}

inline void sub_modulus_u384(thread ulong value[6]) {
    ulong borrow = 0ul;
    for (uint i = 0; i < 4; ++i) {
        ulong tmp = value[i] - MODULUS[i] - borrow;
        borrow = (value[i] < MODULUS[i] + borrow) ? 1ul : 0ul;
        value[i] = tmp;
    }
    for (uint i = 4; i < 6; ++i) {
        ulong tmp = value[i] - borrow;
        borrow = (value[i] < borrow) ? 1ul : 0ul;
        value[i] = tmp;
    }
}

inline Fe native_rns_to_field(RnsFe value) {
    ulong raw[6];
    reconstruct_a_raw(value, raw);
    for (uint iter = 0; iter < 64u; ++iter) {
        if (!geq_mod_u384(raw)) {
            break;
        }
        sub_modulus_u384(raw);
    }

    Fe native = {{raw[0], raw[1], raw[2], raw[3]}};
    return mont_mul(native, FROM_NATIVE_ENCODED);
}

inline Fe rns_mont_mul(Fe a, Fe b) {
    return native_rns_to_field(rns_native_mont_mul(to_native_rns(a), to_native_rns(b)));
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
    uint coeff_index = params.coeff_bits == 0
        ? 0u
        : (reverse_bits_u32(packed_index) >> (32 - params.coeff_bits));
    uint src = poly_index * params.poly_size + block_index * params.message_length + coeff_index;
    output[gid] = coeffs[src];
}

kernel void pack_coefficients_rns(
    device const Fe* coeffs [[buffer(0)]],
    device RnsFe* output [[buffer(1)]],
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
        RnsFe zero = {{0u}};
        output[gid] = zero;
        return;
    }

    uint poly_index = row / params.interleaving_depth;
    uint block_index = row - poly_index * params.interleaving_depth;
    uint packed_index = position >> params.expansion_bits;
    uint coeff_index = params.coeff_bits == 0
        ? 0u
        : (reverse_bits_u32(packed_index) >> (32 - params.coeff_bits));
    uint src = poly_index * params.poly_size + block_index * params.message_length + coeff_index;
    output[gid] = to_native_rns(coeffs[src]);
}

kernel void convert_field_to_rns(
    device const Fe* input [[buffer(0)]],
    device RnsFe* output [[buffer(1)]],
    constant ElementCountParams& params [[buffer(2)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= params.total_elements) {
        return;
    }

    output[gid] = to_native_rns(input[gid]);
}

kernel void convert_rns_to_field(
    device const RnsFe* input [[buffer(0)]],
    device Fe* output [[buffer(1)]],
    constant ElementCountParams& params [[buffer(2)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= params.total_elements) {
        return;
    }

    output[gid] = native_rns_to_field(input[gid]);
}

kernel void stage_ntt(
    device const Fe* input [[buffer(0)]],
    device Fe* output [[buffer(1)]],
    device const Fe* roots [[buffer(2)]],
    constant StageParams& params [[buffer(3)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= params.total_butterflies) {
        return;
    }

    uint butterflies_per_row = params.row_len >> 1;
    uint row = gid / butterflies_per_row;
    uint local = gid - row * butterflies_per_row;
    uint group = local / params.half_len;
    uint k = local - group * params.half_len;

    uint i0 = row * params.row_len + group * (params.half_len << 1) + k;
    uint i1 = i0 + params.half_len;

    Fe even = input[i0];
    Fe odd = input[i1];
    Fe twiddle = roots[k * params.step];
    Fe twiddled = mont_mul(odd, twiddle);

    output[i0] = add_mod(even, twiddled);
    output[i1] = sub_mod(even, twiddled);
}

kernel void stage_ntt_rns(
    device const RnsFe* input_rns [[buffer(0)]],
    device RnsFe* output_rns [[buffer(1)]],
    device const RnsFe* roots [[buffer(2)]],
    constant StageParams& params [[buffer(3)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= params.total_butterflies) {
        return;
    }

    uint butterfly = gid;
    uint row = butterfly / (params.row_len / 2u);
    uint position = butterfly - row * (params.row_len / 2u);
    uint block = position / params.half_len;
    uint j = position - block * params.half_len;

    uint row_start = row * params.row_len;
    uint block_start = row_start + block * params.half_len * 2u;
    uint i0 = block_start + j;
    uint i1 = i0 + params.half_len;

    RnsFe even_rns = input_rns[i0];
    RnsFe odd_rns = input_rns[i1];
    RnsFe twiddle_rns = roots[j * params.step];
    RnsFe twiddled_rns = rns_native_mont_mul(odd_rns, twiddle_rns);

    output_rns[i0] = rns_add(even_rns, twiddled_rns);
    output_rns[i1] = rns_add_two_p(rns_sub(even_rns, twiddled_rns));
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

kernel void mul_field_elements_rns(
    device const Fe* lhs [[buffer(0)]],
    device const Fe* rhs [[buffer(1)]],
    device Fe* output [[buffer(2)]],
    constant FieldMulParams& params [[buffer(3)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= params.count) {
        return;
    }

    output[gid] = rns_mont_mul(lhs[gid], rhs[gid]);
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

kernel void encode_rns_rows_le(
    device const RnsFe* input [[buffer(0)]],
    device uchar* output [[buffer(1)]],
    constant TransposeParams& params [[buffer(2)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= params.total_elements) {
        return;
    }

    uint out_row = gid / params.rows;
    uint out_col = gid - out_row * params.rows;
    uint src = out_col * params.cols + out_row;
    Fe canonical = from_mont(native_rns_to_field(input[src]));
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
        super::{gpu_to_fr, GpuField, MetalBn254Ntt},
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
    fn metal_rns_matches_cpu_for_small_case() {
        let gpu = MetalBn254Ntt::new().unwrap();
        let mut rng = ark_std::test_rng();
        let coeffs: Vec<_> = (0..(1 << 12)).map(|_| Fr::rand(&mut rng)).collect();
        let cpu = reference_interleaved_encode(&[&coeffs], 1 << 11, 1 << 1);
        let matrix = gpu
            .gpu_encode_artifact_with_path(&[&coeffs], 1 << 11, 1 << 1, true)
            .unwrap();
        let gpu = match matrix.storage {
            super::EncodedMatrixStorage::Field(buffer) => gpu
                .engine()
                .unwrap()
                .read_buffer::<GpuField>(&buffer, matrix.rows * matrix.cols)
                .into_iter()
                .map(gpu_to_fr)
                .collect::<Vec<_>>(),
            super::EncodedMatrixStorage::Rns { .. } => {
                unreachable!("encode artifact should materialize field rows")
            }
        };
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
    fn metal_rns_field_mul_matches_cpu() {
        let gpu = MetalBn254Ntt::new().unwrap();
        let mut rng = ark_std::test_rng();
        let lhs: Vec<_> = (0..4096).map(|_| Fr::rand(&mut rng)).collect();
        let rhs: Vec<_> = (0..4096).map(|_| Fr::rand(&mut rng)).collect();
        let expected: Vec<_> = lhs
            .iter()
            .zip(&rhs)
            .map(|(&a, &b)| a * b)
            .collect();
        let actual = gpu.gpu_mul_pairs_with_path(&lhs, &rhs, true).unwrap();
        assert_eq!(actual, expected);
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
    fn metal_rns_commit_hashes_match_cpu() {
        let gpu = MetalBn254Ntt::new().unwrap();
        let mut rng = ark_std::test_rng();
        let coeffs_a: Vec<_> = (0..32).map(|_| Fr::rand(&mut rng)).collect();
        let coeffs_b: Vec<_> = (0..32).map(|_| Fr::rand(&mut rng)).collect();
        let coeffs = [&coeffs_a[..], &coeffs_b[..]];
        let codeword_length = 32usize;
        let interleaving_depth = 2usize;

        let matrix = gpu
            .gpu_commit_artifact_with_path(&coeffs, codeword_length, interleaving_depth, true)
            .unwrap();
        let actual_hashes = gpu.gpu_hash_rows(&matrix).unwrap();

        let cpu_matrix = reference_interleaved_encode(&coeffs, codeword_length, interleaving_depth);
        let expected_hashes = hash_rows_cpu(
            &cpu_matrix,
            codeword_length,
            coeffs.len() * interleaving_depth,
        );
        assert_eq!(actual_hashes, expected_hashes);
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
