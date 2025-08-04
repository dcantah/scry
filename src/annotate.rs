use crate::proc::{Mapping, ProcInfo};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Unknown is a safety fallback for future categories.
pub enum Category {
    Exe,
    ExeData,
    LibText,
    LibRodata,
    LibData,
    LibRelro,
    Heap,
    MainStack,
    ThreadStack,
    GuardPage,
    AnonPrivate,
    AnonShared,
    Vdso,
    Vvar,
    Vsyscall,
    KernelSpecial,
    Memfd,
    Shm,
    LocaleData,
    FileMapping,
    Deleted,
    Unknown,
}

impl Category {
    pub fn short(self) -> &'static str {
        match self {
            Category::Exe => "exe",
            Category::ExeData => "exe-data",
            Category::LibText => "lib-text",
            Category::LibRodata => "lib-ro",
            Category::LibData => "lib-data",
            Category::LibRelro => "lib-relro",
            Category::Heap => "heap",
            Category::MainStack => "stack",
            Category::ThreadStack => "thr-stack",
            Category::GuardPage => "guard",
            Category::AnonPrivate => "anon",
            Category::AnonShared => "anon-shr",
            Category::Vdso => "vdso",
            Category::Vvar => "vvar",
            Category::Vsyscall => "vsyscall",
            Category::KernelSpecial => "kernel",
            Category::Memfd => "memfd",
            Category::Shm => "shm",
            Category::LocaleData => "locale",
            Category::FileMapping => "file",
            Category::Deleted => "deleted",
            Category::Unknown => "?",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Annotation {
    pub category: Category,
    pub headline: String,
    pub details: Vec<String>,
}

pub fn annotate_all(mappings: &[Mapping], info: &ProcInfo) -> Vec<Annotation> {
    let exe_str = info
        .exe_path
        .as_deref()
        .and_then(Path::to_str)
        .map(str::to_string);

    let mut out: Vec<Annotation> = mappings
        .iter()
        .map(|m| annotate_one(m, exe_str.as_deref()))
        .collect();

    // Second pass: detect thread-stack/guard pairs (a small PROT_NONE page
    // adjacent to a larger rw-p anon mapping is the classic glibc pthread
    // stack layout).
    for i in 0..mappings.len() {
        let m = &mappings[i];
        if !is_anonymous(m) {
            continue;
        }
        let perms = m.line.perms;

        // Guard pages have no permissions.
        let is_guard = !perms.r && !perms.w && !perms.x;

        if is_guard {
            // Check neighbour for a rw-p anon big enough to be a stack.
            let neighbour_idx = if i + 1 < mappings.len() {
                Some(i + 1)
            } else {
                None
            };
            let prev_idx = if i > 0 { Some(i - 1) } else { None };
            for &ni in [neighbour_idx, prev_idx].iter().flatten() {
                let n = &mappings[ni];
                // Plausible pthread stack: 256 KB – 256 MB. Defaults are 8 MB;
                // a few apps bump it but multi-GB rw-p anon regions are almost
                // always allocator arenas or runtime reservations, not stacks.
                let n_size = n.size();
                if is_anonymous(n)
                    && n.line.perms.r
                    && n.line.perms.w
                    && !n.line.perms.x
                    && (256 * 1024..=256 * 1024 * 1024).contains(&n_size)
                    && adjacent(m, n)
                {
                    out[i].category = Category::GuardPage;
                    out[i].headline =
                        "Guard page (PROT_NONE). Likely a pthread stack guard.".into();
                    out[ni].category = Category::ThreadStack;
                    out[ni].headline = format!(
                        "Likely a pthread stack ({} KB). Adjacent guard at {:#x}.",
                        n.size() / 1024,
                        m.line.start
                    );
                    break;
                }
            }
        }
    }

    // Third pass: classify consecutive file-backed regions of the same inode
    // as text / rodata / relro / data segments of an ELF.
    let mut i = 0;
    while i < mappings.len() {
        let inode = mappings[i].line.inode;
        let dev = &mappings[i].line.dev;
        if inode == 0 || mappings[i].line.path.is_empty() {
            i += 1;
            continue;
        }
        let mut j = i;
        while j < mappings.len()
            && mappings[j].line.inode == inode
            && mappings[j].line.dev == *dev
            && mappings[j].line.path == mappings[i].line.path
        {
            j += 1;
        }
        // Slice [i, j) is one file group. Classify by perms ordering.
        let group_is_exe = exe_str
            .as_deref()
            .map(|e| e == mappings[i].line.path)
            .unwrap_or(false);
        let group_is_lib = is_library_path(&mappings[i].line.path);
        // Don't reclassify file mappings that pass 1 already identified as
        // locale/memfd/shm/deleted/etc. Only ELF text/data segments.
        if !group_is_exe && !group_is_lib {
            i = j;
            continue;
        }
        for k in i..j {
            let p = mappings[k].line.perms;
            let cat = if group_is_exe {
                if p.x {
                    Category::Exe
                } else if p.w {
                    Category::ExeData
                } else {
                    Category::Exe
                }
            } else if group_is_lib {
                if p.x {
                    Category::LibText
                } else if p.w {
                    Category::LibData
                } else if mappings[k].line.offset != 0 {
                    // After-text read-only chunk is usually relro
                    Category::LibRelro
                } else {
                    Category::LibRodata
                }
            } else {
                Category::FileMapping
            };
            out[k].category = cat;
            out[k].headline = group_headline(cat, &mappings[k]);
        }
        i = j;
    }

    // Recompute detail lines now that categories are final.
    for (idx, a) in out.iter_mut().enumerate() {
        a.details = build_details(a.category, &mappings[idx]);
    }

    out
}

fn adjacent(a: &Mapping, b: &Mapping) -> bool {
    a.line.end == b.line.start || b.line.end == a.line.start
}

fn is_anonymous(m: &Mapping) -> bool {
    m.line.inode == 0 && (m.line.path.is_empty() || m.line.path.starts_with('['))
}

fn is_library_path(p: &str) -> bool {
    // Match .so or .so.NN suffixes
    let name = p.rsplit('/').next().unwrap_or(p);
    name.contains(".so")
}

fn group_headline(cat: Category, m: &Mapping) -> String {
    let path = &m.line.path;
    match cat {
        Category::Exe => format!("Executable text/rodata ({path})"),
        Category::ExeData => format!("Executable .data/.bss ({path})"),
        Category::LibText => format!("Library code (.text) of {}", basename(path)),
        Category::LibRodata => format!("Library .rodata/headers of {}", basename(path)),
        Category::LibRelro => format!("Library RELRO (post-init read-only) of {}", basename(path)),
        Category::LibData => format!("Library writable data of {}", basename(path)),
        Category::FileMapping => format!("File-backed mapping: {path}"),
        _ => path.clone(),
    }
}

fn basename(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

fn annotate_one(m: &Mapping, exe: Option<&str>) -> Annotation {
    let path = m.line.path.as_str();
    let perms = m.line.perms;
    let size = m.size();

    // Deleted-file marker is appended by the kernel.
    let deleted = path.ends_with(" (deleted)");

    let category = if path == "[heap]" {
        Category::Heap
    } else if path == "[stack]" {
        Category::MainStack
    } else if path.starts_with("[stack:") {
        Category::ThreadStack
    } else if path == "[vdso]" {
        Category::Vdso
    } else if path == "[vvar]" || path == "[vvar_vclock]" {
        Category::Vvar
    } else if path == "[vsyscall]" {
        Category::Vsyscall
    } else if path.starts_with('[') {
        Category::KernelSpecial
    } else if path.starts_with("/memfd:") {
        Category::Memfd
    } else if path.starts_with("/dev/shm/") || path.starts_with("/SYSV") {
        Category::Shm
    } else if path.starts_with("/usr/lib/locale/") || path.contains("/locale/") {
        Category::LocaleData
    } else if deleted {
        Category::Deleted
    } else if path.is_empty() {
        if perms.shared {
            Category::AnonShared
        } else if !perms.r && !perms.w && !perms.x {
            Category::GuardPage
        } else {
            Category::AnonPrivate
        }
    } else if exe.map(|e| e == path).unwrap_or(false) {
        if perms.w {
            Category::ExeData
        } else {
            Category::Exe
        }
    } else if is_library_path(path) {
        if perms.x {
            Category::LibText
        } else if perms.w {
            Category::LibData
        } else {
            Category::LibRodata
        }
    } else {
        Category::FileMapping
    };

    let headline = top_line(category, m, size);
    Annotation {
        category,
        headline,
        details: Vec::new(),
    }
}

fn top_line(cat: Category, m: &Mapping, size: u64) -> String {
    match cat {
        Category::Heap => "Process heap. The brk(2)/sbrk(2) area used by malloc for small allocations.".into(),
        Category::MainStack => "Main thread stack. Grows down, sized by RLIMIT_STACK.".into(),
        Category::ThreadStack => format!("Thread stack ({} KB)", size / 1024),
        Category::GuardPage => "Guard page (PROT_NONE). Overflow trap, often a thread-stack guard.".into(),
        Category::Vdso => "vDSO. Kernel-provided fast syscalls (gettimeofday, clock_gettime, etc.).".into(),
        Category::Vvar => "vvar. Read-only kernel data exposed to userspace (clock, rseq).".into(),
        Category::Vsyscall => "vsyscall. Legacy fixed-address syscall page.".into(),
        Category::KernelSpecial => format!("Kernel-special mapping: {}", m.line.path),
        Category::Memfd => format!("memfd: anonymous file in RAM ({})", m.line.path),
        Category::Shm => format!("Shared memory: {}", m.line.path),
        Category::LocaleData => format!("Locale data mmapped by libc: {}", m.line.path),
        Category::Deleted => format!("File mapping whose backing file is gone (hot-replaced?): {}", m.line.path),
        Category::AnonPrivate => anon_headline(m, size),
        Category::AnonShared => "Shared anonymous mapping (MAP_SHARED|MAP_ANONYMOUS). Used for IPC.".into(),
        Category::Exe => format!("Executable text ({})", m.line.path),
        Category::ExeData => format!("Executable .data/.bss ({})", m.line.path),
        Category::LibText => format!("Library text: {}", basename(&m.line.path)),
        Category::LibRodata => format!("Library .rodata: {}", basename(&m.line.path)),
        Category::LibRelro => format!("Library RELRO: {}", basename(&m.line.path)),
        Category::LibData => format!("Library writable data: {}", basename(&m.line.path)),
        Category::FileMapping => format!("File-backed mapping: {}", m.line.path),
        Category::Unknown => "Unclassified".into(),
    }
}

fn anon_headline(m: &Mapping, size: u64) -> String {
    let mb = size / (1024 * 1024);
    let kb = size / 1024;
    let mut s = if mb >= 64 {
        format!(
            "Large anonymous mapping ({mb} MB). Likely a malloc arena (glibc/jemalloc), a JIT heap, or a program-driven mmap."
        )
    } else if kb >= 1024 {
        format!(
            "Anonymous mapping ({mb} MB). Possibly an mmapped malloc chunk (>M_MMAP_THRESHOLD) or an allocator slab."
        )
    } else {
        format!(
            "Small anonymous mapping ({kb} KB). Likely allocator metadata, a TLS slab, or grouped small mmaps."
        )
    };
    if has_flag(m, "nh") {
        s.push_str(" [no THP]");
    }
    if has_flag(m, "hg") {
        s.push_str(" [advise THP]");
    }
    if has_flag(m, "lo") {
        s.push_str(" [mlocked]");
    }
    s
}

fn has_flag(m: &Mapping, f: &str) -> bool {
    m.smaps.vm_flags.iter().any(|x| x == f)
}

fn build_details(cat: Category, m: &Mapping) -> Vec<String> {
    let mut v: Vec<String> = Vec::new();

    match cat {
        Category::Heap => {
            v.push("Allocator: typically glibc malloc using brk() for small allocations.".into());
            v.push("Growth: glibc grows this with brk(2); large allocations bypass it via mmap.".into());
            v.push("Hint: large heap RSS often means many small live allocations or fragmentation.".into());
        }
        Category::MainStack => {
            v.push("Layout: grows downward from the top, soft-limit set by RLIMIT_STACK (`ulimit -s`).".into());
            v.push("Hint: deep recursion or large stack arrays expand this. The committed area equals Rss.".into());
        }
        Category::ThreadStack => {
            v.push("Created by pthread_create. Typical default is 8 MB virtual; only touched pages count toward Rss.".into());
            v.push("Adjacent guard page (PROT_NONE) traps stack overflow.".into());
        }
        Category::GuardPage => {
            v.push("Reserved with mmap PROT_NONE. Any access will SEGV. Used to bound thread stacks or sandboxes.".into());
        }
        Category::Vdso | Category::Vvar | Category::Vsyscall => {
            v.push("Provided by the kernel; reduces syscall cost. Not allocated by the program.".into());
        }
        Category::Exe => {
            v.push("ELF text/rodata of the executable, file-backed and shared across processes that exec it.".into());
        }
        Category::ExeData => {
            v.push("Writable .data/.bss of the executable. Globals and statics live here, and dirty pages count as private.".into());
        }
        Category::LibText => {
            v.push("Shared library .text. Read-only; the page cache is shared between all processes that load this library.".into());
        }
        Category::LibRodata => {
            v.push("Library headers / .rodata. Should have zero Private_Dirty in steady state.".into());
        }
        Category::LibRelro => {
            v.push("Relocation-read-only segment: mprotect()-ed RO by the dynamic loader after relocations.".into());
        }
        Category::LibData => {
            v.push("Library writable globals (.data/.bss). Private_Dirty here means runtime mutated lib state.".into());
        }
        Category::AnonPrivate => {
            v.push("Private anonymous mapping. Created by mmap(MAP_PRIVATE|MAP_ANONYMOUS).".into());
            v.push("Common sources: glibc malloc 'arenas' (one per thread for jemalloc/tcmalloc), large malloc chunks (>128 KB by default), thread TLS, allocator metadata, JIT code heaps.".into());
            v.push("To find the caller: run under a tracer (strace -e mmap), check `pmap -X`, or use heaptrack/jemalloc-prof.".into());
        }
        Category::AnonShared => {
            v.push("Shared anonymous mapping. Used for fork-shared IPC or POSIX shm_open without a name.".into());
        }
        Category::Memfd => {
            v.push("Backed by memfd_create(2). Often used by browsers, sandboxes, and graphics drivers for cross-process buffers.".into());
        }
        Category::Shm => {
            v.push("POSIX or SysV shared memory segment, attached to this process's address space.".into());
        }
        Category::LocaleData => {
            v.push("libc mmaps locale archives for character-class tables. Lots of small mappings here is normal.".into());
        }
        Category::Deleted => {
            v.push("Backing file was unlinked or replaced after mmap. Pages remain mapped; common after package upgrades.".into());
        }
        Category::FileMapping => {
            v.push("Generic file-backed mapping. Could be a data file mmapped for fast IO or a non-ELF resource.".into());
        }
        Category::KernelSpecial | Category::Unknown => {}
    }

    // VmFlags-driven extra hints
    let flags = &m.smaps.vm_flags;
    if flags.iter().any(|f| f == "io") {
        v.push("VmFlags `io`: memory-mapped I/O.".into());
    }
    if flags.iter().any(|f| f == "ht") {
        v.push("VmFlags `ht`: HugeTLB pages.".into());
    }
    if flags.iter().any(|f| f == "lo") {
        v.push("VmFlags `lo`: mlock()'d in RAM.".into());
    }
    if flags.iter().any(|f| f == "dc") {
        v.push("VmFlags `dc`: do not copy on fork.".into());
    }
    if flags.iter().any(|f| f == "de") {
        v.push("VmFlags `de`: do not expand on resize.".into());
    }
    if flags.iter().any(|f| f == "nh") {
        v.push("VmFlags `nh`: kernel won't use THP here.".into());
    }
    if flags.iter().any(|f| f == "hg") {
        v.push("VmFlags `hg`: madvise(MADV_HUGEPAGE) requested.".into());
    }
    if m.smaps.swap_kb > 0 {
        v.push(format!(
            "Swapped out: {} KB (SwapPss {} KB).",
            m.smaps.swap_kb, m.smaps.swap_pss_kb
        ));
    }
    if m.smaps.locked_kb > 0 {
        v.push(format!("Locked in RAM: {} KB.", m.smaps.locked_kb));
    }

    v
}
