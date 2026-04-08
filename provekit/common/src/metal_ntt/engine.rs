use {
    super::{
        field::fr_to_gpu,
        logging::trace_event,
    },
    ark_bn254::Fr,
    ark_ff::Field,
    metal::{
        objc::rc::autoreleasepool, Buffer, CommandQueue, CompileOptions, ComputePipelineState,
        Device, Library, MTLResourceOptions, MTLSize, NSUInteger,
    },
    std::{
        collections::HashMap,
        ffi::c_void,
        mem::size_of,
        ptr,
        sync::{Arc, Mutex},
    },
    whir::algebra::ntt::generator,
};

const SHADER_SOURCE: &str = include_str!("shader.metal");

pub(super) struct MetalRuntime {
    pub(super) device:                Device,
    pub(super) queue:                 CommandQueue,
    pub(super) ntt_stage_pipeline:    ComputePipelineState,
    #[allow(dead_code)]
    pub(super) field_mul_pipeline:    ComputePipelineState,
    pub(super) transpose_pipeline:    ComputePipelineState,
    pub(super) encode_bytes_pipeline: ComputePipelineState,
    pub(super) sha256_pipeline:       ComputePipelineState,
    roots_cache:                      Mutex<HashMap<usize, Arc<Buffer>>>,
}

impl MetalRuntime {
    pub(super) fn new() -> Result<Self, String> {
        autoreleasepool(|| {
            let device = Device::system_default()
                .or_else(|| Device::all().into_iter().next())
                .ok_or_else(|| {
                    "no Metal device found; sandboxed macOS processes may not expose Metal"
                        .to_string()
                })?;
            let options = CompileOptions::new();
            let library = device.new_library_with_source(SHADER_SOURCE, &options)?;

            Ok(Self {
                device: device.to_owned(),
                queue: device.new_command_queue(),
                ntt_stage_pipeline: Self::new_pipeline(&device, &library, "stockham_ntt_stage")?,
                field_mul_pipeline: Self::new_pipeline(
                    &device,
                    &library,
                    "mul_field_elements",
                )?,
                transpose_pipeline: Self::new_pipeline(
                    &device,
                    &library,
                    "transpose_matrix",
                )?,
                encode_bytes_pipeline: Self::new_pipeline(
                    &device,
                    &library,
                    "encode_field_rows_le",
                )?,
                sha256_pipeline: Self::new_pipeline(&device, &library, "sha256_many")?,
                roots_cache: Mutex::new(HashMap::new()),
            })
        })
    }

    pub(super) fn buffer_with_data<T: Copy>(&self, values: &[T]) -> Buffer {
        self.device.new_buffer_with_data(
            values.as_ptr().cast::<c_void>(),
            std::mem::size_of_val(values) as NSUInteger,
            MTLResourceOptions::StorageModeShared,
        )
    }

    pub(super) fn empty_buffer<T>(&self, len: usize) -> Buffer {
        self.device.new_buffer(
            (len * size_of::<T>()) as u64,
            MTLResourceOptions::StorageModeShared,
        )
    }

    pub(super) fn buffer_slice<'a, T>(&self, buffer: &'a Buffer, len: usize) -> &'a [T] {
        let ptr = buffer.contents().cast::<T>();
        unsafe { std::slice::from_raw_parts(ptr, len) }
    }

    pub(super) fn buffer_slice_mut<'a, T>(
        &self,
        buffer: &'a Buffer,
        len: usize,
    ) -> &'a mut [T] {
        let ptr = buffer.contents().cast::<T>();
        unsafe { std::slice::from_raw_parts_mut(ptr, len) }
    }

    pub(super) fn zero_buffer<T>(&self, buffer: &Buffer, len: usize) {
        if len == 0 {
            return;
        }
        unsafe {
            ptr::write_bytes(buffer.contents(), 0, len * size_of::<T>());
        }
    }

    pub(super) fn threads_per_threadgroup(
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

    pub(super) fn roots_buffer(&self, codeword_length: usize) -> Result<Arc<Buffer>, String> {
        let mut cache = self.roots_cache.lock().unwrap();
        if let Some(buffer) = cache.get(&codeword_length) {
            trace_event(format_args!(
                "roots cache hit codeword_length={codeword_length}"
            ));
            return Ok(Arc::clone(buffer));
        }

        let root = generator::<Fr>(codeword_length)
            .ok_or_else(|| format!("no primitive root for order {codeword_length}"))?;
        let stage_count = codeword_length.trailing_zeros() as usize;
        let mut roots = Vec::with_capacity(codeword_length.saturating_sub(1));
        for stage in 0..stage_count {
            let stage_size = 1usize << (stage + 1);
            let half_stage = stage_size >> 1;
            let stage_root = root.pow([(codeword_length / stage_size) as u64]);
            let mut current = Fr::ONE;
            for _ in 0..half_stage {
                roots.push(fr_to_gpu(current));
                current *= stage_root;
            }
        }

        let buffer = Arc::new(self.buffer_with_data(&roots));
        cache.insert(codeword_length, Arc::clone(&buffer));
        trace_event(format_args!(
            "roots cache miss codeword_length={codeword_length}"
        ));
        Ok(buffer)
    }

    fn new_pipeline(
        device: &Device,
        library: &Library,
        function_name: &str,
    ) -> Result<ComputePipelineState, String> {
        library
            .get_function(function_name, None)
            .map_err(|err| err.to_string())
            .and_then(|function| device.new_compute_pipeline_state_with_function(&function))
    }
}
