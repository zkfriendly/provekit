use std::{
    borrow::Cow,
    collections::HashMap,
    env,
    marker::PhantomData,
    mem::size_of,
    sync::{mpsc, Arc, Mutex, OnceLock},
    time::Instant,
};

use ark_bn254::{Fr, FrConfig};
use ark_ff::{BigInt, Field, Fp, MontBackend};
use tracing::info;
use wgpu::util::DeviceExt;
use whir::algebra::ntt::{generator, ReedSolomon};

#[derive(Clone, Copy, Debug, Default)]
pub struct WgpuBn254Ntt;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct GpuField {
    limbs: [u64; 4],
}

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
    _padding:           u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct TransposeParams {
    rows:           u32,
    cols:           u32,
    total_elements: u32,
    _padding:       u32,
}

struct RootTable {
    buffer: wgpu::Buffer,
}

struct EncodedMatrix {
    rows:   usize,
    cols:   usize,
    buffer: wgpu::Buffer,
}

struct WgpuNttEngine {
    adapter_info:   wgpu::AdapterInfo,
    device:         wgpu::Device,
    queue:          wgpu::Queue,
    pack:           wgpu::ComputePipeline,
    stage:          wgpu::ComputePipeline,
    transpose:      wgpu::ComputePipeline,
    roots_by_order: Mutex<HashMap<usize, Arc<RootTable>>>,
}

static ENGINE: OnceLock<Result<Arc<WgpuNttEngine>, String>> = OnceLock::new();

impl WgpuBn254Ntt {
    const DEFAULT_MIN_CODEWORD_LENGTH: usize = 2;
    const PACK_WORKGROUP_SIZE: u32 = 128;
    const STAGE_WORKGROUP_SIZE: u32 = 128;
    const TRANSPOSE_WORKGROUP_SIZE: u32 = 128;

    pub fn new() -> Result<Self, String> {
        if env::var_os("PROVEKIT_DISABLE_WGPU_NTT").is_some() {
            return Err("WGPU NTT disabled via PROVEKIT_DISABLE_WGPU_NTT".into());
        }

        match ENGINE.get_or_init(|| WgpuNttEngine::new().map(Arc::new)) {
            Ok(engine) => {
                info!(
                    backend = ?engine.adapter_info.backend,
                    device = engine.adapter_info.name,
                    driver = engine.adapter_info.driver,
                    "initialized WGPU BN254 NTT backend"
                );
                trace_event(format_args!(
                    "init backend={:?} device={} driver={}",
                    engine.adapter_info.backend, engine.adapter_info.name, engine.adapter_info.driver
                ));
                Ok(Self)
            }
            Err(err) => Err(err.clone()),
        }
    }

    fn engine(&self) -> Result<&Arc<WgpuNttEngine>, String> {
        match ENGINE.get() {
            Some(Ok(engine)) => Ok(engine),
            Some(Err(err)) => Err(err.clone()),
            None => Err("wgpu engine not initialized".into()),
        }
    }

    fn min_codeword_length() -> usize {
        env::var("PROVEKIT_WGPU_NTT_MIN_CODEWORD_LENGTH")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(Self::DEFAULT_MIN_CODEWORD_LENGTH)
    }

    fn should_accelerate(codeword_length: usize, interleaved_coeffs: &[&[Fr]]) -> bool {
        !interleaved_coeffs.is_empty()
            && codeword_length > 1
            && codeword_length.is_power_of_two()
            && codeword_length >= Self::min_codeword_length()
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
                buffer: engine.empty_storage_buffer::<GpuField>(0, "empty-matrix"),
            });
        }
        if !Self::should_accelerate(codeword_length, interleaved_coeffs) {
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
        let total_size_u32 =
            u32::try_from(total_size).map_err(|_| "GPU launch exceeds current 32-bit grid limit")?;
        let total_butterflies_u32 = u32::try_from(total_butterflies)
            .map_err(|_| "GPU launch exceeds current 32-bit grid limit")?;

        trace_event(format_args!(
            "encode rows={} codeword_length={} interleaving_depth={} message_length={} polynomials={}",
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

        let coeffs = engine.storage_buffer_with_data(&coeffs, "coeffs", wgpu::BufferUsages::empty());
        let mut current = engine.empty_storage_buffer::<GpuField>(total_size, "ntt-current");
        let mut scratch = engine.empty_storage_buffer::<GpuField>(total_size, "ntt-scratch");

        let gpu_started = Instant::now();
        let mut encoder = engine
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                label: Some("wgpu-ntt-encode"),
            });

        let pack_params = PackParams {
            poly_size:          poly_size as u32,
            row_len:            codeword_length as u32,
            interleaving_depth: interleaving_depth as u32,
            message_length:     message_length as u32,
            coeff_bits:         message_length.trailing_zeros(),
            expansion_bits:     (codeword_length / message_length).trailing_zeros(),
            total_elements:     total_size_u32,
            _padding:           0,
        };
        engine.dispatch_1d(
            &mut encoder,
            &engine.pack,
            &[
                engine.buffer_binding(&coeffs),
                engine.buffer_binding(&current),
                engine.buffer_binding(&engine.param_buffer(&pack_params, "pack-params")),
            ],
            total_size_u32,
            Self::PACK_WORKGROUP_SIZE,
        );

        let stages = codeword_length.trailing_zeros() as usize;
        for stage in 0..stages {
            let len = 1usize << (stage + 1);
            let half = len / 2;
            let params = StageParams {
                total_butterflies: total_butterflies_u32,
                row_len:           codeword_length as u32,
                half_len:          half as u32,
                step:              (codeword_length / len) as u32,
            };
            engine.dispatch_1d(
                &mut encoder,
                &engine.stage,
                &[
                    engine.buffer_binding(&current),
                    engine.buffer_binding(&scratch),
                    engine.buffer_binding(&roots.buffer),
                    engine.buffer_binding(&engine.param_buffer(&params, "stage-params")),
                ],
                total_butterflies_u32,
                Self::STAGE_WORKGROUP_SIZE,
            );
            std::mem::swap(&mut current, &mut scratch);
        }

        let transpose_params = TransposeParams {
            rows:           rows as u32,
            cols:           codeword_length as u32,
            total_elements: total_size_u32,
            _padding:       0,
        };
        engine.dispatch_1d(
            &mut encoder,
            &engine.transpose,
            &[
                engine.buffer_binding(&current),
                engine.buffer_binding(&scratch),
                engine.buffer_binding(&engine.param_buffer(&transpose_params, "transpose-params")),
            ],
            total_size_u32,
            Self::TRANSPOSE_WORKGROUP_SIZE,
        );

        engine.submit_and_wait(encoder.finish())?;
        let gpu_elapsed = gpu_started.elapsed();

        trace_event(format_args!(
            "encode timings codeword_length={} rows={} pack_us={} roots_us={} gpu_us={} total_us={}",
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
            .read_buffer::<GpuField>(&matrix.buffer, matrix.rows * matrix.cols)?;
        let result = result.into_iter().map(gpu_to_fr).collect();
        trace_event(format_args!(
            "readback timings codeword_length={} rows={} readback_us={}",
            codeword_length,
            matrix.rows,
            readback_started.elapsed().as_micros()
        ));
        Ok(result)
    }
}

impl ReedSolomon<Fr> for WgpuBn254Ntt {
    fn interleaved_encode(
        &self,
        interleaved_coeffs: &[&[Fr]],
        codeword_length: usize,
        interleaving_depth: usize,
    ) -> Vec<Fr> {
        self.gpu_encode(interleaved_coeffs, codeword_length, interleaving_depth)
            .unwrap_or_else(|err| {
                panic!(
                    "WGPU BN254 NTT execution failed for codeword_length={} interleaving_depth={}: {}",
                    codeword_length, interleaving_depth, err
                )
            })
    }
}

impl WgpuNttEngine {
    fn new() -> Result<Self, String> {
        let instance = wgpu::Instance::new(&wgpu::InstanceDescriptor::default());
        let adapter =
            pollster::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions::default()))
                .map_err(|err| err.to_string())?;
        let adapter_info = adapter.get_info();

        if !adapter.features().contains(wgpu::Features::SHADER_INT64) {
            return Err(format!(
                "adapter {:?} ({}) does not support SHADER_INT64",
                adapter_info.backend, adapter_info.name
            ));
        }

        let desc = wgpu::DeviceDescriptor {
            label:               Some("provekit-wgpu-ntt"),
            required_features:   wgpu::Features::SHADER_INT64,
            required_limits:     adapter.limits(),
            experimental_features: wgpu::ExperimentalFeatures::disabled(),
            memory_hints:        wgpu::MemoryHints::Performance,
            trace:               wgpu::Trace::Off,
        };
        let (device, queue) =
            pollster::block_on(adapter.request_device(&desc)).map_err(|err| err.to_string())?;

        let pack = Self::compute_pipeline(&device, "wgpu-pack", &shader_module_source(PACK_SHADER))?;
        let stage =
            Self::compute_pipeline(&device, "wgpu-stage", &shader_module_source(STAGE_SHADER))?;
        let transpose = Self::compute_pipeline(
            &device,
            "wgpu-transpose",
            &shader_module_source(TRANSPOSE_SHADER),
        )?;

        Ok(Self {
            adapter_info,
            device,
            queue,
            pack,
            stage,
            transpose,
            roots_by_order: Mutex::new(HashMap::new()),
        })
    }

    fn compute_pipeline(
        device: &wgpu::Device,
        label: &str,
        source: &str,
    ) -> Result<wgpu::ComputePipeline, String> {
        let compiler = shaderc::Compiler::new().map_err(|err| err.to_string())?;
        let mut options = shaderc::CompileOptions::new().map_err(|err| err.to_string())?;
        options.set_target_env(shaderc::TargetEnv::Vulkan, shaderc::EnvVersion::Vulkan1_2 as u32);
        options.set_target_spirv(shaderc::SpirvVersion::V1_3);
        options.set_optimization_level(shaderc::OptimizationLevel::Performance);
        let artifact = compiler
            .compile_into_spirv(
                source,
                shaderc::ShaderKind::Compute,
                label,
                "main",
                Some(&options),
            )
            .map_err(|err| err.to_string())?;
        let module = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label:  Some(label),
            source: wgpu::ShaderSource::SpirV(Cow::Owned(artifact.as_binary().to_vec())),
        });

        Ok(device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label:               Some(label),
            layout:              None,
            module:              &module,
            entry_point:         Some("main"),
            compilation_options: wgpu::PipelineCompilationOptions::default(),
            cache:               None,
        }))
    }

    fn storage_buffer_with_data<T: Copy>(
        &self,
        values: &[T],
        label: &str,
        extra: wgpu::BufferUsages,
    ) -> wgpu::Buffer {
        self.device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label:    Some(label),
            contents: cast_slice(values),
            usage:    wgpu::BufferUsages::STORAGE
                | wgpu::BufferUsages::COPY_SRC
                | wgpu::BufferUsages::COPY_DST
                | extra,
        })
    }

    fn empty_storage_buffer<T>(&self, len: usize, label: &str) -> wgpu::Buffer {
        self.device.create_buffer(&wgpu::BufferDescriptor {
            label:              Some(label),
            size:               (len * size_of::<T>()) as u64,
            usage:              wgpu::BufferUsages::STORAGE
                | wgpu::BufferUsages::COPY_SRC
                | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        })
    }

    fn param_buffer<T: Copy>(&self, value: &T, label: &str) -> wgpu::Buffer {
        self.storage_buffer_with_data(std::slice::from_ref(value), label, wgpu::BufferUsages::empty())
    }

    fn buffer_binding<'a>(&self, buffer: &'a wgpu::Buffer) -> wgpu::BindingResource<'a> {
        buffer.as_entire_binding()
    }

    fn dispatch_1d(
        &self,
        encoder: &mut wgpu::CommandEncoder,
        pipeline: &wgpu::ComputePipeline,
        resources: &[wgpu::BindingResource<'_>],
        work_items: u32,
        workgroup_size: u32,
    ) {
        if work_items == 0 {
            return;
        }

        let layout = pipeline.get_bind_group_layout(0);
        let entries = resources
            .iter()
            .enumerate()
            .map(|(binding, resource)| wgpu::BindGroupEntry {
                binding:  binding as u32,
                resource: resource.clone(),
            })
            .collect::<Vec<_>>();
        let bind_group = self.device.create_bind_group(&wgpu::BindGroupDescriptor {
            label:   Some("wgpu-ntt-bind-group"),
            layout:  &layout,
            entries: &entries,
        });

        let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
            label:              Some("wgpu-ntt-pass"),
            timestamp_writes:   None,
        });
        pass.set_pipeline(pipeline);
        pass.set_bind_group(0, &bind_group, &[]);
        pass.dispatch_workgroups(work_items.div_ceil(workgroup_size), 1, 1);
    }

    fn submit_and_wait(&self, command_buffer: wgpu::CommandBuffer) -> Result<(), String> {
        self.queue.submit(Some(command_buffer));
        self.device
            .poll(wgpu::PollType::wait_indefinitely())
            .map_err(|err| err.to_string())?;
        Ok(())
    }

    fn read_buffer<T: Copy>(&self, source: &wgpu::Buffer, len: usize) -> Result<Vec<T>, String> {
        let size = (len * size_of::<T>()) as u64;
        let staging = self.device.create_buffer(&wgpu::BufferDescriptor {
            label:              Some("wgpu-readback"),
            size,
            usage:              wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });
        let mut encoder = self
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                label: Some("wgpu-readback-encoder"),
            });
        encoder.copy_buffer_to_buffer(source, 0, &staging, 0, size);
        self.submit_and_wait(encoder.finish())?;

        let slice = staging.slice(..);
        let (tx, rx) = mpsc::channel();
        slice.map_async(wgpu::MapMode::Read, move |result| {
            let _ = tx.send(result);
        });
        self.device
            .poll(wgpu::PollType::wait_indefinitely())
            .map_err(|err| err.to_string())?;
        rx.recv()
            .map_err(|err| err.to_string())?
            .map_err(|err| err.to_string())?;

        let bytes = slice.get_mapped_range();
        let values = cast_bytes_to_vec::<T>(&bytes);
        drop(bytes);
        staging.unmap();
        Ok(values)
    }

    fn root_table(&self, codeword_length: usize) -> Result<Arc<RootTable>, String> {
        let mut cache = self.roots_by_order.lock().unwrap();
        if let Some(table) = cache.get(&codeword_length) {
            trace_event(format_args!("roots cache hit codeword_length={codeword_length}"));
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
            buffer: self.storage_buffer_with_data(&roots, "roots", wgpu::BufferUsages::empty()),
        });
        cache.insert(codeword_length, Arc::clone(&table));
        trace_event(format_args!("roots cache miss codeword_length={codeword_length}"));
        Ok(table)
    }
}

fn trace_event(args: std::fmt::Arguments<'_>) {
    if env::var_os("PROVEKIT_WGPU_NTT_TRACE").is_some() {
        eprintln!("[provekit-wgpu-ntt] {args}");
    }
}

fn fr_to_gpu(value: Fr) -> GpuField {
    GpuField { limbs: value.0 .0 }
}

fn gpu_to_fr(value: GpuField) -> Fr {
    Fp::<MontBackend<FrConfig, 4>, 4>(BigInt(value.limbs), PhantomData)
}

fn cast_slice<T: Copy>(values: &[T]) -> &[u8] {
    unsafe { std::slice::from_raw_parts(values.as_ptr().cast::<u8>(), std::mem::size_of_val(values)) }
}

fn cast_bytes_to_vec<T: Copy>(bytes: &[u8]) -> Vec<T> {
    assert!(bytes.len().is_multiple_of(size_of::<T>()));
    let len = bytes.len() / size_of::<T>();
    unsafe { std::slice::from_raw_parts(bytes.as_ptr().cast::<T>(), len) }.to_vec()
}

fn shader_module_source(entry: &str) -> String {
    format!("{GLSL_COMMON}\n{entry}")
}

const GLSL_COMMON: &str = r#"#version 450
#extension GL_ARB_gpu_shader_int64 : require

struct Fe {
    uint64_t limbs[4];
};

const uint64_t MODULUS[4] = uint64_t[](
    0x43e1f593f0000001ul,
    0x2833e84879b97091ul,
    0xb85045b68181585dul,
    0x30644e72e131a029ul
);

const uint64_t N0_INV = 0xc2e1f593effffffful;

uint reverse_bits_u32(uint x) {
    x = ((x & 0x55555555u) << 1u) | ((x >> 1u) & 0x55555555u);
    x = ((x & 0x33333333u) << 2u) | ((x >> 2u) & 0x33333333u);
    x = ((x & 0x0f0f0f0fu) << 4u) | ((x >> 4u) & 0x0f0f0f0fu);
    x = ((x & 0x00ff00ffu) << 8u) | ((x >> 8u) & 0x00ff00ffu);
    return (x << 16u) | (x >> 16u);
}

bool geq_mod(Fe a) {
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

Fe sub_modulus(Fe a) {
    Fe outv;
    uint64_t borrow = 0ul;
    for (uint i = 0u; i < 4u; ++i) {
        uint64_t tmp = a.limbs[i] - MODULUS[i] - borrow;
        borrow = (a.limbs[i] < MODULUS[i] + borrow) ? 1ul : 0ul;
        outv.limbs[i] = tmp;
    }
    return outv;
}

Fe add_mod(Fe a, Fe b) {
    Fe outv;
    uint64_t carry = 0ul;
    for (uint i = 0u; i < 4u; ++i) {
        uint64_t sum = a.limbs[i] + b.limbs[i];
        uint64_t c1 = sum < a.limbs[i] ? 1ul : 0ul;
        uint64_t sum2 = sum + carry;
        uint64_t c2 = sum2 < sum ? 1ul : 0ul;
        outv.limbs[i] = sum2;
        carry = c1 + c2;
    }
    if (carry != 0ul || geq_mod(outv)) {
        outv = sub_modulus(outv);
    }
    return outv;
}

Fe sub_mod(Fe a, Fe b) {
    Fe outv;
    uint64_t borrow = 0ul;
    for (uint i = 0u; i < 4u; ++i) {
        uint64_t tmp = a.limbs[i] - b.limbs[i] - borrow;
        uint64_t next_borrow = (a.limbs[i] < b.limbs[i] + borrow) ? 1ul : 0ul;
        outv.limbs[i] = tmp;
        borrow = next_borrow;
    }
    if (borrow != 0ul) {
        uint64_t carry = 0ul;
        for (uint i = 0u; i < 4u; ++i) {
            uint64_t sum = outv.limbs[i] + MODULUS[i];
            uint64_t c1 = sum < outv.limbs[i] ? 1ul : 0ul;
            uint64_t sum2 = sum + carry;
            uint64_t c2 = sum2 < sum ? 1ul : 0ul;
            outv.limbs[i] = sum2;
            carry = c1 + c2;
        }
    }
    return outv;
}

void mul_u64(uint64_t a, uint64_t b, out uint64_t hi, out uint64_t lo) {
    uint64_t a0 = a & 0xfffffffful;
    uint64_t a1 = a >> 32u;
    uint64_t b0 = b & 0xfffffffful;
    uint64_t b1 = b >> 32u;

    uint64_t p00 = a0 * b0;
    uint64_t p01 = a0 * b1;
    uint64_t p10 = a1 * b0;
    uint64_t p11 = a1 * b1;

    uint64_t middle = (p00 >> 32u) + (p01 & 0xfffffffful) + (p10 & 0xfffffffful);
    lo = (p00 & 0xfffffffful) | (middle << 32u);
    hi = p11 + (p01 >> 32u) + (p10 >> 32u) + (middle >> 32u);
}

Fe mont_mul(Fe a, Fe b) {
    uint64_t t[5] = uint64_t[5](0ul, 0ul, 0ul, 0ul, 0ul);

    for (uint i = 0u; i < 4u; ++i) {
        uint64_t carry = 0ul;
        for (uint j = 0u; j < 4u; ++j) {
            uint64_t hi;
            uint64_t lo;
            mul_u64(a.limbs[j], b.limbs[i], hi, lo);

            uint64_t sum = t[j] + lo;
            hi += (sum < t[j]) ? 1ul : 0ul;

            uint64_t sum2 = sum + carry;
            hi += (sum2 < sum) ? 1ul : 0ul;

            t[j] = sum2;
            carry = hi;
        }
        t[4] = carry;

        uint64_t m = t[0] * N0_INV;
        carry = 0ul;

        {
            uint64_t hi;
            uint64_t lo;
            mul_u64(m, MODULUS[0], hi, lo);
            uint64_t sum = t[0] + lo;
            hi += (sum < t[0]) ? 1ul : 0ul;
            uint64_t sum2 = sum + carry;
            hi += (sum2 < sum) ? 1ul : 0ul;
            carry = hi;
        }

        for (uint j = 1u; j < 4u; ++j) {
            uint64_t hi;
            uint64_t lo;
            mul_u64(m, MODULUS[j], hi, lo);
            uint64_t sum = t[j] + lo;
            hi += (sum < t[j]) ? 1ul : 0ul;
            uint64_t sum2 = sum + carry;
            hi += (sum2 < sum) ? 1ul : 0ul;
            t[j - 1u] = sum2;
            carry = hi;
        }

        uint64_t sum = t[4] + carry;
        uint64_t c = (sum < t[4]) ? 1ul : 0ul;
        t[3] = sum;
        t[4] = c;
    }

    Fe outv;
    outv.limbs[0] = t[0];
    outv.limbs[1] = t[1];
    outv.limbs[2] = t[2];
    outv.limbs[3] = t[3];
    if (t[4] != 0ul || geq_mod(outv)) {
        outv = sub_modulus(outv);
    }
    return outv;
}
"#;

const PACK_SHADER: &str = r#"
layout(local_size_x = 128, local_size_y = 1, local_size_z = 1) in;

struct PackParams {
    uint poly_size;
    uint row_len;
    uint interleaving_depth;
    uint message_length;
    uint coeff_bits;
    uint expansion_bits;
    uint total_elements;
    uint _padding;
};

layout(std430, binding = 0) readonly buffer CoeffsBuffer {
    Fe coeffs[];
};

layout(std430, binding = 1) buffer OutputBuffer {
    Fe output_values[];
};

layout(std430, binding = 2) readonly buffer ParamsBuffer {
    PackParams params;
};

void main() {
    uint gid = gl_GlobalInvocationID.x;
    if (gid >= params.total_elements) {
        return;
    }

    uint row = gid / params.row_len;
    uint position = gid - row * params.row_len;
    uint expansion_mask = (1u << params.expansion_bits) - 1u;
    if ((position & expansion_mask) != 0u) {
    output_values[gid].limbs[0] = 0ul;
    output_values[gid].limbs[1] = 0ul;
    output_values[gid].limbs[2] = 0ul;
    output_values[gid].limbs[3] = 0ul;
        return;
    }

    uint poly_index = row / params.interleaving_depth;
    uint block_index = row - poly_index * params.interleaving_depth;
    uint packed_index = position >> params.expansion_bits;
    uint coeff_index = params.coeff_bits == 0u
        ? 0u
        : (reverse_bits_u32(packed_index) >> (32u - params.coeff_bits));
    uint src = poly_index * params.poly_size + block_index * params.message_length + coeff_index;
    output_values[gid] = coeffs[src];
}
"#;

const STAGE_SHADER: &str = r#"
layout(local_size_x = 128, local_size_y = 1, local_size_z = 1) in;

struct StageParams {
    uint total_butterflies;
    uint row_len;
    uint half_len;
    uint step;
};

layout(std430, binding = 0) readonly buffer InputBuffer {
    Fe input_values[];
};

layout(std430, binding = 1) buffer OutputBuffer {
    Fe output_values[];
};

layout(std430, binding = 2) readonly buffer RootsBuffer {
    Fe roots[];
};

layout(std430, binding = 3) readonly buffer ParamsBuffer {
    StageParams params;
};

void main() {
    uint gid = gl_GlobalInvocationID.x;
    if (gid >= params.total_butterflies) {
        return;
    }

    uint butterflies_per_row = params.row_len >> 1u;
    uint row = gid / butterflies_per_row;
    uint local = gid - row * butterflies_per_row;
    uint group = local / params.half_len;
    uint k = local - group * params.half_len;

    uint i0 = row * params.row_len + group * (params.half_len << 1u) + k;
    uint i1 = i0 + params.half_len;

    Fe even = input_values[i0];
    Fe odd = input_values[i1];
    Fe twiddled = mont_mul(odd, roots[k * params.step]);

    output_values[i0] = add_mod(even, twiddled);
    output_values[i1] = sub_mod(even, twiddled);
}
"#;

const TRANSPOSE_SHADER: &str = r#"
layout(local_size_x = 128, local_size_y = 1, local_size_z = 1) in;

struct TransposeParams {
    uint rows;
    uint cols;
    uint total_elements;
    uint _padding;
};

layout(std430, binding = 0) readonly buffer InputBuffer {
    Fe input_values[];
};

layout(std430, binding = 1) buffer OutputBuffer {
    Fe output_values[];
};

layout(std430, binding = 2) readonly buffer ParamsBuffer {
    TransposeParams params;
};

void main() {
    uint gid = gl_GlobalInvocationID.x;
    if (gid >= params.total_elements) {
        return;
    }

    uint row = gid / params.cols;
    uint col = gid - row * params.cols;
    uint dst = col * params.rows + row;
    output_values[dst] = input_values[gid];
}
"#;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::WgpuBn254Ntt;
    use ark_bn254::Fr;
    use ark_ff::{AdditiveGroup, UniformRand};
    use whir::{
        algebra::{
            embedding::Identity,
            ntt::{ntt_batch, transpose, ReedSolomon},
        },
        hash::SHA2,
        transcript::{codecs::Empty, DomainSeparator, ProverState, VerifierState},
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

    #[test]
    fn wgpu_matches_cpu_for_small_case() {
        let gpu = WgpuBn254Ntt::new().unwrap();

        let mut rng = ark_std::test_rng();
        let coeffs: Vec<_> = (0..(1 << 12)).map(|_| Fr::rand(&mut rng)).collect();
        let cpu = reference_interleaved_encode(&[&coeffs], 1 << 11, 1 << 1);
        let gpu = gpu.interleaved_encode(&[&coeffs], 1 << 11, 1 << 1);
        assert_eq!(cpu, gpu);
    }

    #[test]
    fn irs_commit_roundtrip_uses_registered_wgpu_ntt() {
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
        let evals = config.open(&mut prover_state, &[&witness]);
        let proof = prover_state.proof();

        let mut verifier_state = VerifierState::new_std(&ds, &proof);
        let commitment = config.receive_commitment(&mut verifier_state).unwrap();
        let verified = config.verify(&mut verifier_state, &[&commitment]).unwrap();
        assert_eq!(verified, evals);
        verifier_state.check_eof().unwrap();
    }
}
