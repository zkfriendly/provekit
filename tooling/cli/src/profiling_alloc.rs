use std::{
    alloc::{GlobalAlloc, Layout, System as SystemAlloc},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    },
};
#[cfg(feature = "tracy")]
use {std::sync::atomic::AtomicBool, tracing_tracy::client::sys as tracy_sys};

/// Minimum allocation size for pooling and pre-faulting. Allocations at or
/// above this threshold are cached on free and reused on subsequent allocs
/// of the same size, so their pages stay physically mapped. This eliminates
/// page-fault storms when rayon threads write to large buffers in parallel.
///
/// 64 KiB is below glibc's mmap threshold (~128 KiB) on Linux, catching all
/// mmap-backed allocations. On macOS, the system malloc has a similar
/// threshold.
const POOL_THRESHOLD: usize = 64 * 1024;

/// Maximum total bytes to hold in the pool. Prevents unbounded memory growth
/// from accumulating differently-sized freed blocks.
const MAX_POOL_BYTES: usize = 3 * 1024 * 1024 * 1024; // 3 GiB

struct PoolEntry {
    ptr: *mut u8,
    size: usize,
    align: usize,
}

// Safety: PoolEntry contains raw pointers that are only accessed under a Mutex.
unsafe impl Send for PoolEntry {}

/// Pre-fault all pages in a large allocation so that later parallel writes
/// from rayon threads don't contend on the kernel's page-table lock.
///
/// # Safety
/// `ptr` must be a valid allocation of at least `size` bytes.
#[cfg(target_os = "linux")]
unsafe fn prefault(ptr: *mut u8, size: usize) {
    if size >= POOL_THRESHOLD && !ptr.is_null() {
        // Page-align address down and size up for madvise.
        let page = 4096usize;
        let aligned_start = (ptr as usize) & !(page - 1);
        let aligned_end = ((ptr as usize) + size + page - 1) & !(page - 1);
        let aligned_ptr = aligned_start as *mut libc::c_void;
        let aligned_size = aligned_end - aligned_start;

        // Use transparent huge pages (2 MiB) to reduce TLB pressure.
        libc::madvise(aligned_ptr, aligned_size, libc::MADV_HUGEPAGE);
        // Pre-fault pages with write semantics (Linux 5.14+).
        // This forces physical page allocation so rayon threads don't
        // all hit anonymous page faults simultaneously.
        libc::madvise(aligned_ptr, aligned_size, libc::MADV_POPULATE_WRITE);
    }
}

/// On non-Linux platforms: prefault is a no-op. The buffer pool handles
/// page reuse across phases, which is the main portable optimization.
/// First-time allocations still incur normal page faults, but subsequent
/// reuses of the same size avoid them entirely.
#[cfg(not(target_os = "linux"))]
unsafe fn prefault(_ptr: *mut u8, _size: usize) {}

/// Custom allocator that pools large freed allocations for reuse and tracks
/// memory statistics.
///
/// ## Buffer pooling
///
/// The proving pipeline allocates and frees large buffers (~500 MB) across
/// sequential phases (two commit phases, multiple WHIR rounds). Without
/// pooling, each free returns pages to the OS (`munmap`), and the next
/// alloc gets fresh virtual pages that trigger page faults when rayon
/// threads write to them in parallel.
///
/// The pool holds freed large blocks and returns them on subsequent allocs
/// of the same size. Since the pages are already physically mapped from
/// previous use, no page faults occur. This works on all platforms without
/// any OS-specific APIs.
pub struct ProfilingAllocator {
    /// Allocated bytes
    current: AtomicUsize,

    /// Maximum allocated bytes (reached so far)
    max: AtomicUsize,

    /// Number of allocations done
    count: AtomicUsize,

    /// Pool of freed large allocations, keyed by (size, align).
    /// Uses `try_lock()` to avoid deadlocks from re-entrant allocation
    /// (e.g., when the Vec itself needs to grow).
    pool: Mutex<Vec<PoolEntry>>,

    /// Total bytes currently held in the pool.
    pool_bytes: AtomicUsize,

    /// Enable Tracy allocation profiling
    #[cfg(feature = "tracy")]
    tracy_enabled: AtomicBool,

    /// Stack depth to include in Tracy allocation profiling
    /// (only used if `tracy_enabled` is true)
    /// **Note.** This makes allocation very slow.
    #[cfg(feature = "tracy")]
    tracy_depth: AtomicUsize,
}

impl ProfilingAllocator {
    pub const fn new() -> Self {
        Self {
            current: AtomicUsize::new(0),
            max: AtomicUsize::new(0),
            count: AtomicUsize::new(0),
            pool: Mutex::new(Vec::new()),
            pool_bytes: AtomicUsize::new(0),

            #[cfg(feature = "tracy")]
            tracy_enabled: AtomicBool::new(false),
            #[cfg(feature = "tracy")]
            tracy_depth: AtomicUsize::new(0),
        }
    }

    pub fn current(&self) -> usize {
        self.current.load(Ordering::SeqCst)
    }

    pub fn max(&self) -> usize {
        self.max.load(Ordering::SeqCst)
    }

    pub fn reset_max(&self) -> usize {
        let current = self.current();
        self.max.store(current, Ordering::SeqCst);
        current
    }

    pub fn count(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }

    #[cfg(feature = "tracy")]
    pub fn enable_tracy(&self, depth: usize) {
        self.tracy_enabled.store(true, Ordering::SeqCst);
        self.tracy_depth.store(depth, Ordering::SeqCst);
    }

    /// Try to find a pooled block matching the requested layout.
    /// Returns the pointer if found, or null if no match.
    fn pool_alloc(&self, layout: Layout) -> *mut u8 {
        if layout.size() < POOL_THRESHOLD {
            return std::ptr::null_mut();
        }
        // Use try_lock to avoid deadlocks from re-entrant allocation
        // (the Vec itself may need to allocate when growing).
        let mut pool = match self.pool.try_lock() {
            Ok(pool) => pool,
            Err(_) => return std::ptr::null_mut(),
        };
        // Search from the end (LIFO) for better cache/TLB locality —
        // the most recently freed block's pages are most likely still
        // resident in cache.
        let pos = pool
            .iter()
            .rposition(|e| e.size == layout.size() && e.align >= layout.align());
        if let Some(idx) = pos {
            let entry = pool.swap_remove(idx);
            self.pool_bytes.fetch_sub(entry.size, Ordering::Relaxed);
            entry.ptr
        } else {
            std::ptr::null_mut()
        }
    }

    /// Return a block to the pool instead of freeing it.
    /// Returns true if pooled, false if the caller should free normally.
    fn pool_dealloc(&self, ptr: *mut u8, layout: Layout) -> bool {
        if layout.size() < POOL_THRESHOLD || ptr.is_null() {
            return false;
        }
        // Don't exceed the pool size cap.
        if self.pool_bytes.load(Ordering::Relaxed) + layout.size() > MAX_POOL_BYTES {
            return false;
        }
        let mut pool = match self.pool.try_lock() {
            Ok(pool) => pool,
            Err(_) => return false,
        };
        pool.push(PoolEntry {
            ptr,
            size: layout.size(),
            align: layout.align(),
        });
        self.pool_bytes
            .fetch_add(layout.size(), Ordering::Relaxed);
        true
    }

    #[allow(unused_variables)] // Conditional compilation may not use all variables
    fn tracy_alloc(&self, size: usize, ptr: *mut u8) {
        // If Tracy profiling is enabled, report this allocation to Tracy.
        #[cfg(feature = "tracy")]
        if self.tracy_enabled.load(Ordering::SeqCst) {
            let depth = self.tracy_depth.load(Ordering::SeqCst);
            if depth == 0 {
                // If depth is 0, we don't capture any stack information
                unsafe {
                    tracy_sys::___tracy_emit_memory_alloc(ptr.cast(), size, 1);
                }
            } else {
                // Capture stack information up to `depth` frames
                unsafe {
                    tracy_sys::___tracy_emit_memory_alloc_callstack(
                        ptr.cast(),
                        size,
                        depth as i32,
                        1,
                    );
                }
            }
        }
    }

    #[allow(unused_variables)] // Conditional compilation may not use all variables
    fn tracy_dealloc(&self, ptr: *mut u8) {
        // If Tracy profiling is enabled, report this deallocation to Tracy.
        #[cfg(feature = "tracy")]
        if self.tracy_enabled.load(Ordering::SeqCst) {
            let depth = self.tracy_depth.load(Ordering::SeqCst);
            if depth == 0 {
                // If depth is 0, we don't capture any stack information
                unsafe {
                    tracy_sys::___tracy_emit_memory_free(ptr.cast(), 1);
                }
            } else {
                // Capture stack information up to `depth` frames
                unsafe {
                    tracy_sys::___tracy_emit_memory_free_callstack(ptr.cast(), depth as i32, 1);
                }
            }
        }
    }
}

#[allow(unsafe_code)]
unsafe impl GlobalAlloc for ProfilingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // Try the pool first — pooled blocks have pages already faulted.
        let ptr = {
            let pooled = self.pool_alloc(layout);
            if !pooled.is_null() {
                pooled
            } else {
                // Pool miss: allocate from the system and pre-fault.
                let ptr = SystemAlloc.alloc(layout);
                prefault(ptr, layout.size());
                ptr
            }
        };
        let size = layout.size();
        let current = self
            .current
            .fetch_add(size, Ordering::SeqCst)
            .wrapping_add(size);
        self.max.fetch_max(current, Ordering::SeqCst);
        self.count.fetch_add(1, Ordering::SeqCst);
        self.tracy_alloc(size, ptr);
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.current.fetch_sub(layout.size(), Ordering::SeqCst);
        self.tracy_dealloc(ptr);
        // Try to pool the block for reuse; fall back to system free.
        if !self.pool_dealloc(ptr, layout) {
            SystemAlloc.dealloc(ptr, layout);
        }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // Try the pool first.
        let ptr = {
            let pooled = self.pool_alloc(layout);
            if !pooled.is_null() {
                // Pooled block may contain stale data — zero it.
                // This is just a memset on already-faulted pages (~20ms for
                // 500MB at memory bandwidth), much cheaper than new page faults.
                std::ptr::write_bytes(pooled, 0, layout.size());
                pooled
            } else {
                // Pool miss: system alloc_zeroed + pre-fault.
                let ptr = SystemAlloc.alloc_zeroed(layout);
                prefault(ptr, layout.size());
                ptr
            }
        };
        let size = layout.size();
        let current = self
            .current
            .fetch_add(size, Ordering::SeqCst)
            .wrapping_add(size);
        self.max.fetch_max(current, Ordering::SeqCst);
        self.count.fetch_add(1, Ordering::SeqCst);
        self.tracy_alloc(size, ptr);
        ptr
    }

    unsafe fn realloc(&self, ptr: *mut u8, old_layout: Layout, new_size: usize) -> *mut u8 {
        self.tracy_dealloc(ptr);
        // Note: the ptr may be a pooled pointer, but it was originally from
        // SystemAlloc.alloc, so SystemAlloc.realloc can handle it.
        let ptr = SystemAlloc.realloc(ptr, old_layout, new_size);
        let old_size = old_layout.size();
        if new_size > old_size {
            // Only prefault the NEW region — the first old_size bytes contain
            // valid data that was moved/copied by realloc.
            prefault(ptr.add(old_size), new_size - old_size);
            let diff = new_size - old_size;
            let current = self
                .current
                .fetch_add(diff, Ordering::SeqCst)
                .wrapping_add(diff);
            self.max.fetch_max(current, Ordering::SeqCst);
            self.count.fetch_add(1, Ordering::SeqCst);
        } else {
            self.current
                .fetch_sub(old_size - new_size, Ordering::SeqCst);
        }
        self.tracy_alloc(new_size, ptr);
        ptr
    }
}
