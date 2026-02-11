use std::{
    alloc::{GlobalAlloc, Layout, System as SystemAlloc},
    sync::atomic::{AtomicUsize, Ordering},
};
#[cfg(feature = "tracy")]
use {std::sync::atomic::AtomicBool, tracing_tracy::client::sys as tracy_sys};

/// Allocations above glibc's mmap threshold (~128 KiB) are backed by mmap.
/// Pre-faulting them avoids page-fault storms when rayon threads write in
/// parallel (PTE spinlock contention from concurrent anonymous faults on
/// the same VMA). We use 64 KiB to be safely below the mmap threshold.
const PREFAULT_THRESHOLD: usize = 64 * 1024;

/// Pre-fault all pages in a large allocation so that later parallel writes
/// from rayon threads don't contend on the kernel's page-table lock.
///
/// # Safety
/// `ptr` must be a valid allocation of at least `size` bytes.
#[cfg(target_os = "linux")]
unsafe fn prefault(ptr: *mut u8, size: usize) {
    if size >= PREFAULT_THRESHOLD && !ptr.is_null() {
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

/// On macOS / other Unix: no MADV_POPULATE_WRITE or MADV_HUGEPAGE.
/// Manually touch every page to force physical allocation before rayon
/// workers hit them concurrently. We use the runtime page size from
/// `sysconf(_SC_PAGESIZE)` and touch one byte per page.
#[cfg(all(unix, not(target_os = "linux")))]
unsafe fn prefault(ptr: *mut u8, size: usize) {
    if size < PREFAULT_THRESHOLD || ptr.is_null() {
        return;
    }

    let page_size_raw = libc::sysconf(libc::_SC_PAGESIZE);
    let page_size = if page_size_raw > 0 {
        usize::try_from(page_size_raw).unwrap_or(4096)
    } else {
        4096
    };

    // Touch one byte per page to force allocation now instead of letting
    // many worker threads trigger first-touch page faults concurrently.
    let mut offset = 0usize;
    while offset < size {
        ptr.add(offset).write_volatile(0u8);
        offset = offset.saturating_add(page_size);
    }

    // Ensure the trailing partial page is touched as well.
    ptr.add(size - 1).write_volatile(0u8);
}

#[cfg(not(unix))]
unsafe fn prefault(_ptr: *mut u8, _size: usize) {}

/// Custom allocator that keeps track of statistics to see program memory
/// consumption.
pub struct ProfilingAllocator {
    /// Allocated bytes
    current: AtomicUsize,

    /// Maximum allocated bytes (reached so far)
    max: AtomicUsize,

    /// Number of allocations done
    count: AtomicUsize,

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
            max:     AtomicUsize::new(0),
            count:   AtomicUsize::new(0),

            #[cfg(feature = "tracy")]
            tracy_enabled:                           AtomicBool::new(false),
            #[cfg(feature = "tracy")]
            tracy_depth:                             AtomicUsize::new(0),
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
        let ptr = SystemAlloc.alloc(layout);
        let size = layout.size();
        prefault(ptr, size);
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
        SystemAlloc.dealloc(ptr, layout);
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = SystemAlloc.alloc_zeroed(layout);
        let size = layout.size();
        prefault(ptr, size);
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
