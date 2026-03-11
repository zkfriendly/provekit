use {
    ark_bn254::{Fr, FrConfig},
    ark_ff::{BigInt, Field, Fp, MontBackend},
    cudarc::{
        driver::{
            CudaContext, CudaFunction, CudaSlice, CudaStream, DeviceRepr, DriverError,
            LaunchConfig, PushKernelArg, ValidAsZeroBits,
        },
        nvrtc::{compile_ptx_with_opts, CompileOptions},
    },
    std::{
        collections::{hash_map::DefaultHasher, HashMap},
        env,
        fs,
        marker::PhantomData,
        mem::size_of,
        path::PathBuf,
        hash::{Hash as _, Hasher},
        sync::{Arc, Mutex, OnceLock},
        time::Instant,
    },
    tracing::info,
    whir::{
        algebra::ntt::{generator, ArkNtt, ReedSolomon},
        engines::EngineId,
        hash::{Hash, SHA2},
        protocols::irs_commit::{AcceleratedCommit, AcceleratedCommitter, MatrixRows},
    },
};

#[derive(Clone, Copy, Debug, Default)]
pub struct CudaBn254Ntt;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct GpuField {
    limbs: [u64; 4],
}

unsafe impl DeviceRepr for GpuField {}
unsafe impl ValidAsZeroBits for GpuField {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct StageParams {
    total_butterflies: u64,
    row_len:           u64,
    half_len:          u64,
    step:              u64,
}

unsafe impl DeviceRepr for StageParams {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct TiledStageParams {
    rows:         u64,
    row_len:      u64,
    tile_len:     u64,
    stage_count:  u32,
    _padding:     u32,
}

unsafe impl DeviceRepr for TiledStageParams {}

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

unsafe impl DeviceRepr for PackParams {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct TransposeParams {
    rows:           u64,
    cols:           u64,
    total_elements: u64,
}

unsafe impl DeviceRepr for TransposeParams {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct HashManyParams {
    row_fields: u64,
    count:      u64,
}

unsafe impl DeviceRepr for HashManyParams {}

struct RootTable {
    buffer: CudaSlice<GpuField>,
}

struct EncodedMatrix {
    rows:   usize,
    cols:   usize,
    buffer: CudaSlice<GpuField>,
}

struct CudaNttEngine {
    ctx:            Arc<CudaContext>,
    pack:           CudaFunction,
    stage_tiled:    CudaFunction,
    stage:          CudaFunction,
    transpose:      CudaFunction,
    sha256_rows:    CudaFunction,
    roots_by_order: Mutex<HashMap<usize, Arc<RootTable>>>,
    workspaces:     Mutex<Vec<EncodeWorkspace>>,
}

struct EncodeWorkspace {
    stream:      Arc<CudaStream>,
    current:     Option<CudaSlice<GpuField>>,
    scratch:     Option<CudaSlice<GpuField>>,
    hash_output: Option<CudaSlice<u8>>,
}

struct CudaMatrixRows {
    rows:   usize,
    cols:   usize,
    buffer: CudaSlice<GpuField>,
    stream: Arc<CudaStream>,
}

static ENGINE: OnceLock<Result<Arc<CudaNttEngine>, String>> = OnceLock::new();

struct WorkspaceLease<'a> {
    engine:    &'a CudaNttEngine,
    workspace: Option<EncodeWorkspace>,
}

impl CudaBn254Ntt {
    const DEFAULT_MIN_CODEWORD_LENGTH: usize = 32;
    const DEFAULT_ROOT_CACHE_CAPACITY: usize = 8;
    const TILED_STAGE_TILE_LEN: usize = 512;
    const BLOCK_DIM: u32 = 256;

    pub fn new() -> Result<Self, String> {
        if env::var_os("PROVEKIT_DISABLE_CUDA_NTT").is_some() {
            return Err("CUDA NTT disabled via PROVEKIT_DISABLE_CUDA_NTT".into());
        }

        match ENGINE.get_or_init(|| CudaNttEngine::new().map(Arc::new)) {
            Ok(engine) => {
                let (major, minor) = engine.ctx.compute_capability().map_err(driver_err)?;
                info!(
                    device = engine.ctx.name().map_err(driver_err)?,
                    compute_capability = format!("{major}.{minor}"),
                    "initialized CUDA BN254 NTT backend"
                );
                trace_event(format_args!(
                    "init device={} compute_capability={major}.{minor}",
                    engine.ctx.name().map_err(driver_err)?
                ));
                Ok(Self)
            }
            Err(err) => Err(err.clone()),
        }
    }

    fn engine(&self) -> Result<&Arc<CudaNttEngine>, String> {
        match ENGINE.get() {
            Some(Ok(engine)) => Ok(engine),
            Some(Err(err)) => Err(err.clone()),
            None => Err("cuda engine not initialized".into()),
        }
    }

    fn min_codeword_length() -> usize {
        env::var("PROVEKIT_CUDA_NTT_MIN_CODEWORD_LENGTH")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(Self::DEFAULT_MIN_CODEWORD_LENGTH)
    }

    fn root_cache_capacity() -> usize {
        env::var("PROVEKIT_CUDA_NTT_ROOT_CACHE_CAPACITY")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|&v| v > 0)
            .unwrap_or(Self::DEFAULT_ROOT_CACHE_CAPACITY)
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

    fn cpu_encode(
        interleaved_coeffs: &[&[Fr]],
        codeword_length: usize,
        interleaving_depth: usize,
    ) -> Vec<Fr> {
        ArkNtt::<Fr>::default().interleaved_encode(
            interleaved_coeffs,
            codeword_length,
            interleaving_depth,
        )
    }

    fn grid_1d(work_items: usize) -> LaunchConfig {
        let grid = (work_items as u32).div_ceil(Self::BLOCK_DIM);
        LaunchConfig {
            grid_dim: (grid, 1, 1),
            block_dim: (Self::BLOCK_DIM, 1, 1),
            shared_mem_bytes: 0,
        }
    }

    fn grid_tiled(rows: usize, tiles_per_row: usize, tile_len: usize) -> LaunchConfig {
        LaunchConfig {
            grid_dim: ((rows * tiles_per_row) as u32, 1, 1),
            block_dim: ((tile_len / 2) as u32, 1, 1),
            shared_mem_bytes: (tile_len * size_of::<GpuField>()) as u32,
        }
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
                rows: 0,
                cols: 0,
                buffer: engine
                    .ctx
                    .new_stream()
                    .map_err(driver_err)?
                    .clone_htod(&Vec::<GpuField>::new())
                    .map_err(driver_err)?,
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
        if total_size > u32::MAX as usize || total_butterflies > u32::MAX as usize {
            return Err("CUDA kernel launch exceeds current 32-bit grid limit".into());
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
        let mut workspace = engine.checkout_workspace()?;
        let coeffs_stream = Arc::clone(&workspace.workspace.as_ref().unwrap().stream);
        let mut coeffs = unsafe {
            engine
                .ctx
                .alloc_pinned::<GpuField>(interleaved_coeffs.len() * poly_size)
                .map_err(driver_err)?
        };
        {
            let coeffs_slice = coeffs.as_mut_slice().map_err(driver_err)?;
            for (poly_index, poly) in interleaved_coeffs.iter().enumerate() {
                let dst = &mut coeffs_slice[poly_index * poly_size..(poly_index + 1) * poly_size];
                for (dst_field, value) in dst.iter_mut().zip(poly.iter().copied()) {
                    *dst_field = fr_to_gpu(value);
                }
            }
        }
        let coeffs_dev = coeffs_stream.clone_htod(&coeffs).map_err(driver_err)?;
        let pack_elapsed = pack_started.elapsed();

        let roots_started = Instant::now();
        let roots = engine.root_table(codeword_length)?;
        let roots_elapsed = roots_started.elapsed();
        workspace.ensure_current_buffer(total_size)?;
        workspace.ensure_scratch_buffer(total_size)?;
        let workspace_inner = workspace.workspace.as_mut().unwrap();
        let stream = Arc::clone(&workspace_inner.stream);
        let current = workspace_inner.current.as_mut().unwrap();
        let scratch = workspace_inner.scratch.as_mut().unwrap();
        stream.memset_zeros(current).map_err(driver_err)?;
        stream.memset_zeros(scratch).map_err(driver_err)?;

        let pack_params = PackParams {
            poly_size: poly_size as u64,
            row_len: codeword_length as u64,
            interleaving_depth: interleaving_depth as u64,
            message_length: message_length as u64,
            coeff_bits: message_length.trailing_zeros(),
            expansion_bits: (codeword_length / message_length).trailing_zeros(),
            total_elements: total_size as u64,
        };

        let gpu_started = Instant::now();
        {
            let mut launch = stream.launch_builder(&engine.pack);
            launch.arg(&coeffs_dev);
            launch.arg(&mut *current);
            launch.arg(&pack_params);
            unsafe { launch.launch(Self::grid_1d(total_size)) }.map_err(driver_err)?;
        }

        let mut current_is_workspace_current = true;
        let stages = codeword_length.trailing_zeros() as usize;
        let tiled_stage_count = stages.min(Self::TILED_STAGE_TILE_LEN.trailing_zeros() as usize);
        if tiled_stage_count > 0 {
            let tile_len = 1usize << tiled_stage_count;
            let tiles_per_row = codeword_length / tile_len;
            let params = TiledStageParams {
                rows: rows as u64,
                row_len: codeword_length as u64,
                tile_len: tile_len as u64,
                stage_count: tiled_stage_count as u32,
                _padding: 0,
            };
            let mut launch = stream.launch_builder(&engine.stage_tiled);
            let current_view = current.as_view();
            launch.arg(&current_view);
            launch.arg(&mut *scratch);
            launch.arg(&roots.buffer);
            launch.arg(&params);
            unsafe { launch.launch(Self::grid_tiled(rows, tiles_per_row, tile_len)) }
                .map_err(driver_err)?;
            current_is_workspace_current = false;
        }
        for stage in tiled_stage_count..stages {
            let len = 1usize << (stage + 1);
            let half = len / 2;
            let params = StageParams {
                total_butterflies: total_butterflies as u64,
                row_len: codeword_length as u64,
                half_len: half as u64,
                step: (codeword_length / len) as u64,
            };
            if current_is_workspace_current {
                let mut launch = stream.launch_builder(&engine.stage);
                let current_view = current.as_view();
                launch.arg(&current_view);
                launch.arg(&mut *scratch);
                launch.arg(&roots.buffer);
                launch.arg(&params);
                unsafe { launch.launch(Self::grid_1d(total_butterflies)) }.map_err(driver_err)?;
            } else {
                let mut launch = stream.launch_builder(&engine.stage);
                let scratch_view = scratch.as_view();
                launch.arg(&scratch_view);
                launch.arg(&mut *current);
                launch.arg(&roots.buffer);
                launch.arg(&params);
                unsafe { launch.launch(Self::grid_1d(total_butterflies)) }.map_err(driver_err)?;
            }
            current_is_workspace_current = !current_is_workspace_current;
        }

        let mut output = stream
            .alloc_zeros::<GpuField>(total_size)
            .map_err(driver_err)?;
        let transpose_params = TransposeParams {
            rows: rows as u64,
            cols: codeword_length as u64,
            total_elements: total_size as u64,
        };
        {
            if current_is_workspace_current {
                let mut launch = stream.launch_builder(&engine.transpose);
                let current_view = current.as_view();
                launch.arg(&current_view);
                launch.arg(&mut output);
                launch.arg(&transpose_params);
                unsafe { launch.launch(Self::grid_1d(total_size)) }.map_err(driver_err)?;
            } else {
                let mut launch = stream.launch_builder(&engine.transpose);
                let scratch_view = scratch.as_view();
                launch.arg(&scratch_view);
                launch.arg(&mut output);
                launch.arg(&transpose_params);
                unsafe { launch.launch(Self::grid_1d(total_size)) }.map_err(driver_err)?;
            }
        }
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
            rows: codeword_length,
            cols: rows,
            buffer: output,
        })
    }

    fn gpu_hash_rows(&self, matrix: &EncodedMatrix) -> Result<Vec<Hash>, String> {
        let total_started = Instant::now();
        let engine = self.engine()?;
        if matrix.rows == 0 {
            return Ok(Vec::new());
        }

        if matrix.rows > u32::MAX as usize {
            return Err("CUDA row hashing launch exceeds current 32-bit grid limit".into());
        }

        let bytes_started = Instant::now();
        let mut workspace = engine.checkout_workspace()?;
        let hash_stream = Arc::clone(&workspace.workspace.as_ref().unwrap().stream);
        let hash_buffer = workspace.hash_output_buffer(matrix.rows * size_of::<Hash>())?;
        let mut hash_view = hash_buffer.slice_mut(..matrix.rows * size_of::<Hash>());
        let bytes_elapsed = bytes_started.elapsed();
        let hash_params = HashManyParams {
            row_fields: matrix.cols as u64,
            count:      matrix.rows as u64,
        };

        let gpu_started = Instant::now();
        {
            let mut launch = hash_stream.launch_builder(&engine.sha256_rows);
            launch.arg(&matrix.buffer);
            launch.arg(&mut hash_view);
            launch.arg(&hash_params);
            unsafe { launch.launch(Self::grid_1d(matrix.rows)) }.map_err(driver_err)?;
        }
        hash_stream.synchronize().map_err(driver_err)?;
        let gpu_elapsed = gpu_started.elapsed();

        let readback_started = Instant::now();
        let mut bytes = vec![0u8; matrix.rows * size_of::<Hash>()];
        hash_stream.memcpy_dtoh(&hash_view, &mut bytes).map_err(driver_err)?;
        hash_stream.synchronize().map_err(driver_err)?;
        let mut hashes = vec![Hash::default(); matrix.rows];
        for (dst, chunk) in hashes.iter_mut().zip(bytes.chunks_exact(size_of::<Hash>())) {
            dst.0.copy_from_slice(chunk);
        }
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
        let stream = matrix.buffer.stream();
        let mut result = vec![GpuField::default(); matrix.rows * matrix.cols];
        stream.memcpy_dtoh(&matrix.buffer, &mut result).map_err(driver_err)?;
        stream.synchronize().map_err(driver_err)?;
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

impl ReedSolomon<Fr> for CudaBn254Ntt {
    fn interleaved_encode(
        &self,
        interleaved_coeffs: &[&[Fr]],
        codeword_length: usize,
        interleaving_depth: usize,
    ) -> Vec<Fr> {
        if !Self::should_accelerate(codeword_length, interleaved_coeffs, None) {
            return Self::cpu_encode(interleaved_coeffs, codeword_length, interleaving_depth);
        }

        self.gpu_encode(interleaved_coeffs, codeword_length, interleaving_depth)
            .unwrap_or_else(|err| {
                panic!(
                    "CUDA BN254 NTT execution failed for codeword_length={} interleaving_depth={}: {}",
                    codeword_length, interleaving_depth, err
                )
            })
    }
}

impl AcceleratedCommitter<Fr> for CudaBn254Ntt {
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
        let buffer_stream = Arc::clone(matrix.buffer.stream());
        let rows = Arc::new(CudaMatrixRows {
            rows: matrix.rows,
            cols: matrix.cols,
            buffer: matrix.buffer,
            stream: buffer_stream,
        });
        Ok(Some(AcceleratedCommit {
            matrix: rows,
            leaf_hashes,
        }))
    }
}

impl std::fmt::Debug for CudaMatrixRows {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CudaMatrixRows")
            .field("rows", &self.rows)
            .field("cols", &self.cols)
            .finish()
    }
}

impl MatrixRows<Fr> for CudaMatrixRows {
    fn len(&self) -> usize {
        self.rows * self.cols
    }

    fn read_rows(&self, indices: &[usize]) -> Vec<Fr> {
        if indices.is_empty() {
            return Vec::new();
        }
        for &row in indices {
            assert!(row < self.rows, "row index out of bounds");
        }
        let mut unique_rows = indices.to_vec();
        unique_rows.sort_unstable();
        unique_rows.dedup();

        let mut unique_data = HashMap::with_capacity(unique_rows.len());
        let mut segment_start = 0usize;
        while segment_start < unique_rows.len() {
            let start_row = unique_rows[segment_start];
            let mut segment_end = segment_start + 1;
            while segment_end < unique_rows.len()
                && unique_rows[segment_end] == unique_rows[segment_end - 1] + 1
            {
                segment_end += 1;
            }
            let row_count = segment_end - segment_start;
            let start = start_row * self.cols;
            let end = start + row_count * self.cols;
            let view = self.buffer.slice(start..end);
            let mut segment = vec![GpuField::default(); row_count * self.cols];
            self.stream
                .memcpy_dtoh(&view, &mut segment)
                .unwrap_or_else(|err| panic!("CUDA matrix row read failed: {err}"));
            for offset in 0..row_count {
                let row = start_row + offset;
                let row_start = offset * self.cols;
                let row_end = row_start + self.cols;
                unique_data.insert(row, segment[row_start..row_end].to_vec());
            }
            segment_start = segment_end;
        }
        self.stream
            .synchronize()
            .unwrap_or_else(|err| panic!("CUDA matrix row read failed: {err}"));
        let mut out = Vec::with_capacity(indices.len() * self.cols);
        for &row in indices {
            out.extend(unique_data[&row].iter().copied().map(gpu_to_fr));
        }
        out
    }
}

impl CudaNttEngine {
    fn new() -> Result<Self, String> {
        let ctx = CudaContext::new(0).map_err(driver_err)?;
        let (major, minor) = ctx.compute_capability().map_err(driver_err)?;
        let ptx = compile_cached_ptx("ntt", CUDA_NTT_SOURCE, arch_for_compute_capability(major, minor))?;
        let module = ctx.load_module(ptx).map_err(driver_err)?;

        Ok(Self {
            ctx,
            pack: module.load_function("pack_coefficients").map_err(driver_err)?,
            stage_tiled: module.load_function("stage_ntt_tiled").map_err(driver_err)?,
            stage: module.load_function("stage_ntt").map_err(driver_err)?,
            transpose: module.load_function("transpose_matrix").map_err(driver_err)?,
            sha256_rows: module.load_function("sha256_field_rows").map_err(driver_err)?,
            roots_by_order: Mutex::new(HashMap::new()),
            workspaces: Mutex::new(Vec::new()),
        })
    }

    fn checkout_workspace(&self) -> Result<WorkspaceLease<'_>, String> {
        let workspace = self.workspaces.lock().unwrap().pop();
        let workspace = match workspace {
            Some(workspace) => workspace,
            None => EncodeWorkspace::new(Arc::clone(&self.ctx))?,
        };
        Ok(WorkspaceLease {
            engine: self,
            workspace: Some(workspace),
        })
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
            buffer: self
                .ctx
                .new_stream()
                .map_err(driver_err)?
                .clone_htod(&roots)
                .map_err(driver_err)?,
        });
        if cache.len() >= CudaBn254Ntt::root_cache_capacity() {
            if let Some(evict_key) = cache.keys().copied().min() {
                cache.remove(&evict_key);
            }
        }
        cache.insert(codeword_length, Arc::clone(&table));
        trace_event(format_args!("roots cache miss codeword_length={codeword_length}"));
        Ok(table)
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

impl EncodeWorkspace {
    fn new(ctx: Arc<CudaContext>) -> Result<Self, String> {
        Ok(Self {
            stream: ctx.new_stream().map_err(driver_err)?,
            current: None,
            scratch: None,
            hash_output: None,
        })
    }

    fn ensure_current_buffer(&mut self, len: usize) -> Result<(), String> {
        ensure_buffer(&self.stream, &mut self.current, len).map(|_| ())
    }

    fn ensure_scratch_buffer(&mut self, len: usize) -> Result<(), String> {
        ensure_buffer(&self.stream, &mut self.scratch, len).map(|_| ())
    }

    fn hash_output_buffer<'a>(
        &'a mut self,
        len: usize,
    ) -> Result<&'a mut CudaSlice<u8>, String> {
        ensure_buffer(&self.stream, &mut self.hash_output, len)
    }
}

impl Drop for WorkspaceLease<'_> {
    fn drop(&mut self) {
        if let Some(workspace) = self.workspace.take() {
            self.engine.workspaces.lock().unwrap().push(workspace);
        }
    }
}

impl WorkspaceLease<'_> {
    fn ensure_current_buffer(&mut self, len: usize) -> Result<(), String> {
        self.workspace.as_mut().unwrap().ensure_current_buffer(len)
    }

    fn ensure_scratch_buffer(&mut self, len: usize) -> Result<(), String> {
        self.workspace.as_mut().unwrap().ensure_scratch_buffer(len)
    }

    fn hash_output_buffer(&mut self, len: usize) -> Result<&mut CudaSlice<u8>, String> {
        self.workspace.as_mut().unwrap().hash_output_buffer(len)
    }
}

fn ensure_buffer<'a, T: DeviceRepr + ValidAsZeroBits>(
    stream: &Arc<CudaStream>,
    slot: &'a mut Option<CudaSlice<T>>,
    len: usize,
) -> Result<&'a mut CudaSlice<T>, String> {
    let needs_alloc = slot.as_ref().is_none_or(|buffer| buffer.len() < len);
    if needs_alloc {
        *slot = Some(stream.alloc_zeros::<T>(len).map_err(driver_err)?);
    }
    Ok(slot.as_mut().unwrap())
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
    if env::var_os("PROVEKIT_CUDA_NTT_TRACE").is_some() {
        eprintln!("[provekit-cuda-ntt] {args}");
    }
}

fn fr_to_gpu(value: Fr) -> GpuField {
    GpuField { limbs: value.0 .0 }
}

fn gpu_to_fr(value: GpuField) -> Fr {
    Fp::<MontBackend<FrConfig, 4>, 4>(BigInt(value.limbs), PhantomData)
}

const CUDA_NTT_SOURCE: &str = r#"
typedef unsigned int uint;
typedef unsigned long long ulong;

struct Fe {
    ulong limbs[4];
};

struct StageParams {
    ulong total_butterflies;
    ulong row_len;
    ulong half_len;
    ulong step;
};

struct TiledStageParams {
    ulong rows;
    ulong row_len;
    ulong tile_len;
    uint stage_count;
    uint _padding;
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

struct HashManyParams {
    ulong row_fields;
    ulong count;
};

__device__ __constant__ ulong MODULUS[4] = {
    0x43e1f593f0000001ull,
    0x2833e84879b97091ull,
    0xb85045b68181585dull,
    0x30644e72e131a029ull
};

__device__ __constant__ ulong N0_INV = 0xc2e1f593efffffffull;
__device__ __constant__ Fe FE_ONE = {{1ull, 0ull, 0ull, 0ull}};

__device__ __constant__ uint SHA256_K[64] = {
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

__device__ __forceinline__ uint reverse_bits_u32(uint x) {
    return __brev(x);
}

__device__ __forceinline__ bool geq_mod(Fe a) {
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

__device__ __forceinline__ Fe sub_modulus(Fe a) {
    Fe out;
    ulong borrow = 0ull;
    for (uint i = 0; i < 4; ++i) {
        ulong tmp = a.limbs[i] - MODULUS[i] - borrow;
        borrow = (a.limbs[i] < MODULUS[i] + borrow) ? 1ull : 0ull;
        out.limbs[i] = tmp;
    }
    return out;
}

__device__ __forceinline__ Fe add_mod(Fe a, Fe b) {
    Fe out;
    ulong carry = 0ull;
    for (uint i = 0; i < 4; ++i) {
        ulong sum = a.limbs[i] + b.limbs[i];
        ulong c1 = sum < a.limbs[i] ? 1ull : 0ull;
        ulong sum2 = sum + carry;
        ulong c2 = sum2 < sum ? 1ull : 0ull;
        out.limbs[i] = sum2;
        carry = c1 + c2;
    }
    if (carry != 0ull || geq_mod(out)) {
        out = sub_modulus(out);
    }
    return out;
}

__device__ __forceinline__ Fe sub_mod(Fe a, Fe b) {
    Fe out;
    ulong borrow = 0ull;
    for (uint i = 0; i < 4; ++i) {
        ulong tmp = a.limbs[i] - b.limbs[i] - borrow;
        ulong next_borrow = (a.limbs[i] < b.limbs[i] + borrow) ? 1ull : 0ull;
        out.limbs[i] = tmp;
        borrow = next_borrow;
    }
    if (borrow != 0ull) {
        ulong carry = 0ull;
        for (uint i = 0; i < 4; ++i) {
            ulong sum = out.limbs[i] + MODULUS[i];
            ulong c1 = sum < out.limbs[i] ? 1ull : 0ull;
            ulong sum2 = sum + carry;
            ulong c2 = sum2 < sum ? 1ull : 0ull;
            out.limbs[i] = sum2;
            carry = c1 + c2;
        }
    }
    return out;
}

__device__ __forceinline__ Fe mont_mul(Fe a, Fe b) {
    ulong t[5] = {0ull, 0ull, 0ull, 0ull, 0ull};

    for (uint i = 0; i < 4; ++i) {
        ulong carry = 0ull;
        for (uint j = 0; j < 4; ++j) {
            ulong lo = a.limbs[j] * b.limbs[i];
            ulong hi = __umul64hi(a.limbs[j], b.limbs[i]);

            ulong sum = t[j] + lo;
            hi += (sum < t[j]) ? 1ull : 0ull;

            ulong sum2 = sum + carry;
            hi += (sum2 < sum) ? 1ull : 0ull;

            t[j] = sum2;
            carry = hi;
        }
        t[4] = carry;

        ulong m = t[0] * N0_INV;
        carry = 0ull;

        {
            ulong lo = m * MODULUS[0];
            ulong hi = __umul64hi(m, MODULUS[0]);
            ulong sum = t[0] + lo;
            hi += (sum < t[0]) ? 1ull : 0ull;
            ulong sum2 = sum + carry;
            hi += (sum2 < sum) ? 1ull : 0ull;
            carry = hi;
        }

        for (uint j = 1; j < 4; ++j) {
            ulong lo = m * MODULUS[j];
            ulong hi = __umul64hi(m, MODULUS[j]);
            ulong sum = t[j] + lo;
            hi += (sum < t[j]) ? 1ull : 0ull;
            ulong sum2 = sum + carry;
            hi += (sum2 < sum) ? 1ull : 0ull;
            t[j - 1] = sum2;
            carry = hi;
        }

        ulong sum = t[4] + carry;
        ulong c = (sum < t[4]) ? 1ull : 0ull;
        t[3] = sum;
        t[4] = c;
    }

    Fe out;
    out.limbs[0] = t[0];
    out.limbs[1] = t[1];
    out.limbs[2] = t[2];
    out.limbs[3] = t[3];
    if (t[4] != 0ull || geq_mod(out)) {
        out = sub_modulus(out);
    }
    return out;
}

__device__ __forceinline__ Fe from_mont(Fe a) {
    return mont_mul(a, FE_ONE);
}

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

extern "C" __global__ void pack_coefficients(
    const Fe* coeffs,
    Fe* output,
    PackParams params
) {
    ulong gid = (ulong)blockIdx.x * (ulong)blockDim.x + (ulong)threadIdx.x;
    if (gid >= params.total_elements) {
        return;
    }

    ulong row = gid / params.row_len;
    ulong position = gid - row * params.row_len;
    ulong expansion_mask = (1ull << params.expansion_bits) - 1ull;
    if ((position & expansion_mask) != 0ull) {
        Fe zero = {{0ull, 0ull, 0ull, 0ull}};
        output[gid] = zero;
        return;
    }

    ulong poly_index = row / params.interleaving_depth;
    ulong block_index = row - poly_index * params.interleaving_depth;
    uint packed_index = (uint)(position >> params.expansion_bits);
    uint coeff_index = params.coeff_bits == 0u
        ? 0u
        : (reverse_bits_u32(packed_index) >> (32u - params.coeff_bits));
    ulong src = poly_index * params.poly_size + block_index * params.message_length + coeff_index;
    output[gid] = coeffs[src];
}

extern "C" __global__ void stage_ntt(
    const Fe* input,
    Fe* output,
    const Fe* roots,
    StageParams params
) {
    ulong gid = (ulong)blockIdx.x * (ulong)blockDim.x + (ulong)threadIdx.x;
    if (gid >= params.total_butterflies) {
        return;
    }

    ulong butterflies_per_row = params.row_len >> 1;
    ulong row = gid / butterflies_per_row;
    ulong local = gid - row * butterflies_per_row;
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

extern "C" __global__ void stage_ntt_tiled(
    const Fe* input,
    Fe* output,
    const Fe* roots,
    TiledStageParams params
) {
    extern __shared__ Fe tile[];

    ulong block = (ulong)blockIdx.x;
    ulong tiles_per_row = params.row_len / params.tile_len;
    ulong row = block / tiles_per_row;
    ulong tile_index = block - row * tiles_per_row;
    ulong tile_start = row * params.row_len + tile_index * params.tile_len;
    uint tid = (uint)threadIdx.x;
    ulong half_tile = params.tile_len >> 1;

    if (row >= params.rows || tid >= half_tile) {
        return;
    }

    tile[tid] = input[tile_start + tid];
    tile[half_tile + tid] = input[tile_start + half_tile + tid];
    __syncthreads();

    for (uint stage = 0u; stage < params.stage_count; ++stage) {
        ulong len = 1ull << (stage + 1u);
        ulong half = len >> 1u;
        ulong group = tid / half;
        ulong k = tid - group * half;
        ulong i0 = group * len + k;
        ulong i1 = i0 + half;
        ulong step = params.row_len / len;
        Fe even = tile[i0];
        Fe odd = tile[i1];
        Fe twiddle = roots[k * step];
        Fe twiddled = mont_mul(odd, twiddle);
        tile[i0] = add_mod(even, twiddled);
        tile[i1] = sub_mod(even, twiddled);
        __syncthreads();
    }

    output[tile_start + tid] = tile[tid];
    output[tile_start + half_tile + tid] = tile[half_tile + tid];
}

extern "C" __global__ void transpose_matrix(
    const Fe* input,
    Fe* output,
    TransposeParams params
) {
    ulong gid = (ulong)blockIdx.x * (ulong)blockDim.x + (ulong)threadIdx.x;
    if (gid >= params.total_elements) {
        return;
    }

    ulong row = gid / params.cols;
    ulong col = gid - row * params.cols;
    ulong dst = col * params.rows + row;
    output[dst] = input[gid];
}

__device__ __forceinline__ uint word_from_bytes(
    unsigned char b0,
    unsigned char b1,
    unsigned char b2,
    unsigned char b3
) {
    return ((uint)b0 << 24) | ((uint)b1 << 16) | ((uint)b2 << 8) | (uint)b3;
}

__device__ __forceinline__ void write_field_words(Fe field, uint* w, uint word_offset) {
    #pragma unroll
    for (uint limb = 0; limb < 4; ++limb) {
        ulong value = field.limbs[limb];
        unsigned char b0 = (unsigned char)(value & 0xffull);
        unsigned char b1 = (unsigned char)((value >> 8) & 0xffull);
        unsigned char b2 = (unsigned char)((value >> 16) & 0xffull);
        unsigned char b3 = (unsigned char)((value >> 24) & 0xffull);
        unsigned char b4 = (unsigned char)((value >> 32) & 0xffull);
        unsigned char b5 = (unsigned char)((value >> 40) & 0xffull);
        unsigned char b6 = (unsigned char)((value >> 48) & 0xffull);
        unsigned char b7 = (unsigned char)((value >> 56) & 0xffull);
        w[word_offset + limb * 2u + 0u] = word_from_bytes(b0, b1, b2, b3);
        w[word_offset + limb * 2u + 1u] = word_from_bytes(b4, b5, b6, b7);
    }
}

extern "C" __global__ void sha256_field_rows(
    const Fe* input,
    unsigned char* output,
    HashManyParams params
) {
    ulong gid = (ulong)blockIdx.x * (ulong)blockDim.x + (ulong)threadIdx.x;
    if (gid >= params.count) {
        return;
    }

    const Fe* row = input + gid * params.row_fields;
    ulong row_size = params.row_fields * 32ull;
    ulong total_blocks = (row_size + 9ull + 63ull) / 64ull;
    ulong bit_len = row_size * 8ull;
    ulong full_field_pairs = params.row_fields >> 1u;
    bool odd_field_count = (params.row_fields & 1ull) != 0ull;

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
        #pragma unroll
        for (uint i = 0; i < 16; ++i) {
            w[i] = 0u;
        }

        if (block < full_field_pairs) {
            ulong field_index = block * 2ull;
            write_field_words(from_mont(row[field_index]), w, 0u);
            write_field_words(from_mont(row[field_index + 1ull]), w, 8u);
        } else if (odd_field_count && block == full_field_pairs) {
            write_field_words(from_mont(row[params.row_fields - 1ull]), w, 0u);
            w[8] = 0x80000000u;
            w[14] = (uint)(bit_len >> 32);
            w[15] = (uint)(bit_len & 0xffffffffull);
        } else {
            w[0] = 0x80000000u;
            w[14] = (uint)(bit_len >> 32);
            w[15] = (uint)(bit_len & 0xffffffffull);
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
        super::CudaBn254Ntt,
        ark_bn254::Fr,
        ark_ff::{AdditiveGroup, UniformRand},
        whir::{
            algebra::ntt::{ntt_batch, transpose, ReedSolomon},
            hash::{Hash, Sha2, HashEngine, SHA2},
            protocols::irs_commit::AcceleratedCommitter,
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
        use whir::protocols::matrix_commit::Encodable;

        let engine = Sha2::new();
        let mut encoder = <Fr as Encodable>::encoder();
        let bytes = encoder.encode(matrix);
        let mut out = vec![Hash::default(); num_rows];
        engine.hash_many(num_cols * Fr::encoded_size(), bytes, &mut out);
        out
    }

    #[test]
    fn cuda_matches_cpu_for_small_case() {
        let gpu = CudaBn254Ntt::new().unwrap();
        let mut rng = ark_std::test_rng();
        let coeffs: Vec<_> = (0..(1 << 12)).map(|_| Fr::rand(&mut rng)).collect();
        let cpu = reference_interleaved_encode(&[&coeffs], 1 << 11, 1 << 1);
        let gpu = gpu.interleaved_encode(&[&coeffs], 1 << 11, 1 << 1);
        assert_eq!(cpu, gpu);
    }

    #[test]
    fn cuda_accelerated_commit_matches_cpu() {
        let gpu = CudaBn254Ntt::new().unwrap();
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
        let cpu_matrix =
            reference_interleaved_encode(&coeffs, codeword_length, interleaving_depth);
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

        let expected_hashes = hash_rows_cpu(
            &cpu_matrix,
            codeword_length,
            coeffs.len() * interleaving_depth,
        );
        assert_eq!(accelerated.leaf_hashes, expected_hashes);
    }
}
