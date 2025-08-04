use crate::annotate::{Annotation, Category, annotate_all};
use crate::perms::{UserInfo, current as current_user};
use crate::proc::{
    CLK_TCK, Capabilities, CgroupSection, FdEntry, Mapping, Namespaces, ProcInfo, ProcStat,
    SecurityInfo, SocketInfo, ThreadEntry, TreeRow, count_fds, enumerate_pids, load_mappings,
    load_proc_info, proc_uid, read_capabilities, read_cgroup, read_cgroup_v2_resources,
    read_cmdline, read_environ, read_fds, read_io, read_kstack, read_kstack_tid, read_limits,
    read_namespaces, read_process_tree, read_security, read_socket_table, read_stat, read_threads,
    read_user_map,
};
use crate::strace::StraceSession;
use anyhow::Result;
use std::collections::HashMap;
use std::time::Instant;

// ---------------------------------------------------------------------------
// Screen routing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Picker,
    Menu,
    Maps,
    Threads,
    Fds,
    Limits,
    Cgroup,
    Environ,
    KernelStack,
    Syscalls,
    Tree,
    SignalSend,
    Capabilities,
    Namespaces,
    Security,
}

impl Screen {
    pub fn title(self) -> &'static str {
        match self {
            Screen::Picker => "process picker",
            Screen::Menu => "menu",
            Screen::Maps => "memory map",
            Screen::Threads => "threads",
            Screen::Fds => "open files",
            Screen::Limits => "resource limits",
            Screen::Cgroup => "cgroup",
            Screen::Environ => "environment",
            Screen::KernelStack => "kernel stack",
            Screen::Syscalls => "syscall trace",
            Screen::Tree => "child process tree",
            Screen::SignalSend => "send signal",
            Screen::Capabilities => "capabilities",
            Screen::Namespaces => "namespaces",
            Screen::Security => "security overview",
        }
    }
}

// ---------------------------------------------------------------------------
// Menu
// ---------------------------------------------------------------------------

pub struct MenuItem {
    pub screen: Screen,
    pub label: &'static str,
    pub desc: &'static str,
    pub needs_root: bool,
}

pub const MENU_ITEMS: &[MenuItem] = &[
    MenuItem {
        screen: Screen::Picker,
        label: "Switch process",
        desc: "Return to the process picker to attach to a different pid",
        needs_root: false,
    },
    MenuItem {
        screen: Screen::Maps,
        label: "Memory map",
        desc: "Annotated VMA table with smaps metrics. Heap, stacks, libraries, anon mmaps.",
        needs_root: false,
    },
    MenuItem {
        screen: Screen::Threads,
        label: "Threads",
        desc: "Per-thread tid, name, state, accumulated CPU ticks",
        needs_root: false,
    },
    MenuItem {
        screen: Screen::Tree,
        label: "Child process tree",
        desc: "Recursive descendants of this pid. Enter on a child re-attaches to it.",
        needs_root: false,
    },
    MenuItem {
        screen: Screen::Fds,
        label: "Open file descriptors",
        desc: "Sockets, pipes, files, eventfds.",
        needs_root: false,
    },
    MenuItem {
        screen: Screen::Limits,
        label: "Resource limits",
        desc: "RLIMIT_* values (stack, nofile, memlock, ...)",
        needs_root: false,
    },
    MenuItem {
        screen: Screen::Cgroup,
        label: "Cgroup membership",
        desc: "v2 unified hierarchy path and controllers",
        needs_root: false,
    },
    MenuItem {
        screen: Screen::Environ,
        label: "Environment variables",
        desc: "/proc/<pid>/environ. Captured at exec time, not live.",
        needs_root: false,
    },
    MenuItem {
        screen: Screen::Capabilities,
        label: "Capabilities",
        desc: "Decoded CAP_* bits across inheritable/permitted/effective/bounding/ambient sets.",
        needs_root: false,
    },
    MenuItem {
        screen: Screen::Namespaces,
        label: "Namespaces",
        desc: "Per-namespace inodes (pid/mnt/net/user/...). Flags which differ from the host.",
        needs_root: false,
    },
    MenuItem {
        screen: Screen::Security,
        label: "Security overview",
        desc: "Seccomp mode, NoNewPrivs, AppArmor/SELinux label, Yama ptrace policy, sandbox verdict.",
        needs_root: false,
    },
    MenuItem {
        screen: Screen::KernelStack,
        label: "Kernel stack",
        desc: "Where the task is parked inside the kernel right now",
        needs_root: true,
    },
    MenuItem {
        screen: Screen::Syscalls,
        label: "Syscall trace (strace)",
        desc: "Live syscall stream. Attaches strace -p in the background.",
        needs_root: true,
    },
    MenuItem {
        screen: Screen::SignalSend,
        label: "Send signal",
        desc: "Pick a signal (all 31 standard + SIGRTMIN..SIGRTMAX) and send it to this process.",
        needs_root: false,
    },
];

// ---------------------------------------------------------------------------
// Per-screen state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortBy {
    Address,
    Size,
    Rss,
    Pss,
    Category,
}

impl SortBy {
    /// Human-readable name shown in the title bar and footer hint.
    pub fn label(self) -> &'static str {
        match self {
            SortBy::Address => "Address",
            SortBy::Size => "Size",
            SortBy::Rss => "RSS (resident set)",
            SortBy::Pss => "PSS (proportional share)",
            SortBy::Category => "Category",
        }
    }

    /// Column header text this sort key corresponds to. Used to render the
    /// sort arrow next to the right column.
    pub fn column_header(self) -> &'static str {
        match self {
            SortBy::Address => "Address range",
            SortBy::Size => "Size",
            SortBy::Rss => "Rss",
            SortBy::Pss => "Pss",
            SortBy::Category => "Cat",
        }
    }

    pub fn next(self) -> Self {
        match self {
            SortBy::Address => SortBy::Size,
            SortBy::Size => SortBy::Rss,
            SortBy::Rss => SortBy::Pss,
            SortBy::Pss => SortBy::Category,
            SortBy::Category => SortBy::Address,
        }
    }
}

pub struct MapsState {
    pub mappings: Vec<Mapping>,
    pub annotations: Vec<Annotation>,
    pub view: Vec<usize>,
    pub selected: usize,
    pub sort: SortBy,
    pub sort_desc: bool,
    pub filter: String,
    pub editing_filter: bool,
}

impl MapsState {
    pub fn new(mappings: Vec<Mapping>, annotations: Vec<Annotation>) -> Self {
        let mut s = MapsState {
            mappings,
            annotations,
            view: Vec::new(),
            selected: 0,
            sort: SortBy::Address,
            sort_desc: false,
            filter: String::new(),
            editing_filter: false,
        };
        s.rebuild_view();
        s
    }

    pub fn rebuild_view(&mut self) {
        let mut idx: Vec<usize> = (0..self.mappings.len())
            .filter(|&i| self.matches_filter(i))
            .collect();
        match self.sort {
            SortBy::Address => idx.sort_by_key(|&i| self.mappings[i].line.start),
            SortBy::Size => idx.sort_by_key(|&i| self.mappings[i].size()),
            SortBy::Rss => idx.sort_by_key(|&i| self.mappings[i].smaps.rss_kb),
            SortBy::Pss => idx.sort_by_key(|&i| self.mappings[i].smaps.pss_kb),
            SortBy::Category => idx.sort_by_key(|&i| category_rank(self.annotations[i].category)),
        }
        if self.sort_desc {
            idx.reverse();
        }
        self.view = idx;
        if self.selected >= self.view.len() {
            self.selected = self.view.len().saturating_sub(1);
        }
    }

    fn matches_filter(&self, i: usize) -> bool {
        if self.filter.is_empty() {
            return true;
        }
        let q = self.filter.to_ascii_lowercase();
        let m = &self.mappings[i];
        let a = &self.annotations[i];
        m.line.path.to_ascii_lowercase().contains(&q)
            || a.category.short().contains(q.as_str())
            || a.headline.to_ascii_lowercase().contains(&q)
    }

    pub fn current_mapping(&self) -> Option<&Mapping> {
        self.view.get(self.selected).map(|&i| &self.mappings[i])
    }

    pub fn current_annotation(&self) -> Option<&Annotation> {
        self.view.get(self.selected).map(|&i| &self.annotations[i])
    }

    pub fn move_cursor(&mut self, delta: i32) {
        if self.view.is_empty() {
            self.selected = 0;
            return;
        }
        let n = self.view.len() as i32;
        let s = (self.selected as i32 + delta).clamp(0, n - 1);
        self.selected = s as usize;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PickerSort {
    Cpu,
    Rss,
    Pid,
    Name,
    User,
}

impl PickerSort {
    pub fn label(self) -> &'static str {
        match self {
            PickerSort::Cpu => "cpu",
            PickerSort::Rss => "rss",
            PickerSort::Pid => "pid",
            PickerSort::Name => "name",
            PickerSort::User => "user",
        }
    }
    pub fn next(self) -> Self {
        match self {
            PickerSort::Cpu => PickerSort::Rss,
            PickerSort::Rss => PickerSort::Pid,
            PickerSort::Pid => PickerSort::Name,
            PickerSort::Name => PickerSort::User,
            PickerSort::User => PickerSort::Cpu,
        }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)] // uid/cpu_ticks are kept on the entry for future sort/views.
pub struct PickerEntry {
    pub pid: i32,
    pub comm: String,
    pub state: char,
    pub uid: u32,
    pub user: String,
    pub rss_kb: u64,
    pub cpu_percent: f64,
    pub cpu_ticks: u64,
    pub cmdline: String,
}

pub struct PickerState {
    pub entries: Vec<PickerEntry>,
    pub view: Vec<usize>,
    pub selected: usize,
    pub sort: PickerSort,
    pub sort_desc: bool,
    pub filter: String,
    pub editing_filter: bool,
    pub user_map: HashMap<u32, String>,
    /// Per-pid cumulative cpu ticks at the previous sample, used to compute %CPU.
    last_sample: HashMap<i32, u64>,
    last_sample_at: Option<Instant>,
}

impl PickerState {
    pub fn new() -> Self {
        let mut s = PickerState {
            entries: Vec::new(),
            view: Vec::new(),
            selected: 0,
            sort: PickerSort::Cpu,
            sort_desc: true,
            filter: String::new(),
            editing_filter: false,
            user_map: read_user_map(),
            last_sample: HashMap::new(),
            last_sample_at: None,
        };
        s.refresh();
        s
    }

    pub fn refresh(&mut self) {
        let now = Instant::now();
        let dt = self
            .last_sample_at
            .map(|t| now.duration_since(t).as_secs_f64())
            .unwrap_or(0.0);
        let mut new_sample = HashMap::new();
        let mut entries = Vec::new();
        for pid in enumerate_pids() {
            // /proc/<pid>/stat is a single mandatory read. If it fails the
            // process disappeared between enumerate_pids and now.
            let Ok(stat) = read_stat(pid) else { continue };
            let ticks = stat.utime_ticks + stat.stime_ticks;
            let cpu_percent = if dt > 0.0 {
                let prev = self.last_sample.get(&pid).copied().unwrap_or(ticks);
                100.0 * ticks.saturating_sub(prev) as f64 / (CLK_TCK as f64 * dt)
            } else {
                0.0
            };
            new_sample.insert(pid, ticks);
            let uid = proc_uid(pid).unwrap_or(u32::MAX);
            let user = self
                .user_map
                .get(&uid)
                .cloned()
                .unwrap_or_else(|| uid.to_string());
            let rss_kb = stat.rss_pages.saturating_mul(4); // assume 4 KB pages
            let cmd = read_cmdline(pid);
            let cmdline = if cmd.is_empty() {
                format!("[{}]", stat.comm) // kernel thread
            } else {
                cmd
            };
            entries.push(PickerEntry {
                pid,
                comm: stat.comm,
                state: stat.state,
                uid,
                user,
                rss_kb,
                cpu_percent,
                cpu_ticks: ticks,
                cmdline,
            });
        }
        self.entries = entries;
        self.last_sample = new_sample;
        self.last_sample_at = Some(now);
        self.rebuild_view();
    }

    pub fn rebuild_view(&mut self) {
        let mut idx: Vec<usize> = (0..self.entries.len())
            .filter(|&i| self.matches_filter(i))
            .collect();
        match self.sort {
            PickerSort::Cpu => idx.sort_by(|&a, &b| {
                self.entries[a]
                    .cpu_percent
                    .partial_cmp(&self.entries[b].cpu_percent)
                    .unwrap_or(std::cmp::Ordering::Equal)
            }),
            PickerSort::Rss => idx.sort_by_key(|&i| self.entries[i].rss_kb),
            PickerSort::Pid => idx.sort_by_key(|&i| self.entries[i].pid),
            PickerSort::Name => idx.sort_by(|&a, &b| self.entries[a].comm.cmp(&self.entries[b].comm)),
            PickerSort::User => idx.sort_by(|&a, &b| self.entries[a].user.cmp(&self.entries[b].user)),
        }
        if self.sort_desc {
            idx.reverse();
        }
        self.view = idx;
        if self.selected >= self.view.len() {
            self.selected = self.view.len().saturating_sub(1);
        }
    }

    fn matches_filter(&self, i: usize) -> bool {
        if self.filter.is_empty() {
            return true;
        }
        let q = self.filter.to_ascii_lowercase();
        let e = &self.entries[i];
        e.comm.to_ascii_lowercase().contains(&q)
            || e.cmdline.to_ascii_lowercase().contains(&q)
            || e.user.to_ascii_lowercase().contains(&q)
            || e.pid.to_string().contains(&q)
    }

    pub fn current(&self) -> Option<&PickerEntry> {
        self.view.get(self.selected).map(|&i| &self.entries[i])
    }

    pub fn move_cursor(&mut self, delta: i32) {
        if self.view.is_empty() {
            self.selected = 0;
            return;
        }
        let n = self.view.len() as i32;
        let s = (self.selected as i32 + delta).clamp(0, n - 1);
        self.selected = s as usize;
    }
}

/// One thread's kernel stack, plus the metadata we need to label it. Populated
/// by the Kernel Stack screen. Either one entry (main thread, default) or one
/// per TID in /proc/<pid>/task/* when the user toggles all-threads mode.
#[derive(Debug, Clone, Default)]
pub struct ThreadStack {
    pub tid: i32,
    pub name: String,
    pub state: String,
    pub stack: Option<String>,
    pub err: Option<String>,
}

#[derive(Default)]
pub struct ScrollState {
    pub offset: usize,
}


impl ScrollState {
    /// Move the scroll offset by `delta`, clamped so the bottom of the content
    /// never scrolls past the bottom of the visible area. `total` is the
    /// number of content lines; `viewport` is the height in rows available
    /// to render them.
    pub fn scroll_by(&mut self, delta: i32, total: usize, viewport: usize) {
        let next = (self.offset as i32 + delta).max(0) as usize;
        let max = total.saturating_sub(viewport);
        self.offset = next.min(max);
    }
}

// ---------------------------------------------------------------------------
// Persistent process summary refreshed periodically
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct CpuSample {
    pub proc_ticks: u64,
    pub when: Option<Instant>,
}

#[derive(Default)]
pub struct ProcSummary {
    pub info: ProcInfo,
    pub stat: ProcStat,
    pub io: HashMap<String, u64>,
    pub cgroup: Vec<(String, String, String)>,
    pub cpu_percent: f64,
    pub open_fds: Option<usize>,
    last_sample: CpuSample,
}

impl ProcSummary {
    pub fn collect(pid: i32) -> Result<Self> {
        let info = load_proc_info(pid)?;
        let stat = read_stat(pid).unwrap_or_default();
        let io = read_io(pid).unwrap_or_default();
        let cgroup = read_cgroup(pid).unwrap_or_default();
        let proc_ticks = stat.utime_ticks + stat.stime_ticks;
        let open_fds = count_fds(pid);
        Ok(ProcSummary {
            info,
            stat,
            io,
            cgroup,
            cpu_percent: 0.0,
            open_fds,
            last_sample: CpuSample {
                proc_ticks,
                when: Some(Instant::now()),
            },
        })
    }

    pub fn refresh(&mut self, pid: i32) -> Result<()> {
        self.info = load_proc_info(pid)?;
        self.stat = read_stat(pid).unwrap_or_default();
        self.io = read_io(pid).unwrap_or_default();
        self.cgroup = read_cgroup(pid).unwrap_or_default();
        self.open_fds = count_fds(pid);
        let proc_ticks = self.stat.utime_ticks + self.stat.stime_ticks;
        let now = Instant::now();
        if let Some(prev_when) = self.last_sample.when {
            let dt = now.duration_since(prev_when).as_secs_f64();
            let d_proc = proc_ticks.saturating_sub(self.last_sample.proc_ticks) as f64;
            if dt > 0.0 {
                // proc_ticks are in CLK_TCK units. CPU% per single core:
                //   (d_proc / CLK_TCK) seconds of CPU used per `dt` real seconds.
                self.cpu_percent = 100.0 * d_proc / (CLK_TCK as f64 * dt);
            }
        }
        self.last_sample = CpuSample {
            proc_ticks,
            when: Some(now),
        };
        Ok(())
    }

    pub fn cgroup_path(&self) -> String {
        // v2 has a single line "0::/path"; v1 has many. Pick v2 if present,
        // else the first hybrid line.
        if let Some(v2) = self.cgroup.iter().find(|c| c.0 == "0") {
            return v2.2.clone();
        }
        self.cgroup
            .first()
            .map(|c| c.2.clone())
            .unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SignalEntry {
    pub num: i32,
    pub name: String,
    pub desc: String,
}

/// Build the full signal list: 31 standard signals + every real-time signal
/// in `[SIGRTMIN, SIGRTMAX]`. The RT range is queried at runtime because glibc
/// reserves the first few RT signals for NPTL, so the minimum varies.
pub fn all_signals() -> Vec<SignalEntry> {
    let std_signals: &[(i32, &str, &str)] = &[
        (libc::SIGHUP,    "SIGHUP",    "hangup; daemons often treat as reload-config"),
        (libc::SIGINT,    "SIGINT",    "interrupt (what Ctrl-C sends)"),
        (libc::SIGQUIT,   "SIGQUIT",   "quit + core dump (what Ctrl-\\ sends)"),
        (libc::SIGILL,    "SIGILL",    "illegal instruction"),
        (libc::SIGTRAP,   "SIGTRAP",   "trace/breakpoint trap (debuggers)"),
        (libc::SIGABRT,   "SIGABRT",   "abort, usually from assert() or abort()"),
        (libc::SIGBUS,    "SIGBUS",    "bus error (bad memory access)"),
        (libc::SIGFPE,    "SIGFPE",    "floating-point or integer math exception"),
        (libc::SIGKILL,   "SIGKILL",   "force kill, cannot be caught or ignored"),
        (libc::SIGUSR1,   "SIGUSR1",   "user-defined signal 1"),
        (libc::SIGSEGV,   "SIGSEGV",   "segmentation fault"),
        (libc::SIGUSR2,   "SIGUSR2",   "user-defined signal 2"),
        (libc::SIGPIPE,   "SIGPIPE",   "wrote to a closed pipe / socket"),
        (libc::SIGALRM,   "SIGALRM",   "alarm clock (timer)"),
        (libc::SIGTERM,   "SIGTERM",   "polite terminate (default for kill)"),
        (libc::SIGSTKFLT, "SIGSTKFLT", "stack fault on coprocessor (unused on x86)"),
        (libc::SIGCHLD,   "SIGCHLD",   "child status changed (exited, stopped, continued)"),
        (libc::SIGCONT,   "SIGCONT",   "resume a stopped process"),
        (libc::SIGSTOP,   "SIGSTOP",   "pause execution, cannot be caught"),
        (libc::SIGTSTP,   "SIGTSTP",   "terminal stop (what Ctrl-Z sends)"),
        (libc::SIGTTIN,   "SIGTTIN",   "background process tried to read from tty"),
        (libc::SIGTTOU,   "SIGTTOU",   "background process tried to write to tty"),
        (libc::SIGURG,    "SIGURG",    "urgent data available on socket"),
        (libc::SIGXCPU,   "SIGXCPU",   "CPU time limit exceeded (RLIMIT_CPU)"),
        (libc::SIGXFSZ,   "SIGXFSZ",   "file size limit exceeded (RLIMIT_FSIZE)"),
        (libc::SIGVTALRM, "SIGVTALRM", "virtual alarm (process CPU time)"),
        (libc::SIGPROF,   "SIGPROF",   "profiling timer expired"),
        (libc::SIGWINCH,  "SIGWINCH",  "terminal window resized"),
        (libc::SIGIO,     "SIGIO",     "I/O ready (async I/O, also SIGPOLL)"),
        (libc::SIGPWR,    "SIGPWR",    "power failure / UPS event"),
        (libc::SIGSYS,    "SIGSYS",    "bad system call (often raised by seccomp)"),
    ];
    let mut out: Vec<SignalEntry> = std_signals
        .iter()
        .map(|&(n, name, desc)| SignalEntry {
            num: n,
            name: name.to_string(),
            desc: desc.to_string(),
        })
        .collect();

    // SIGRTMIN/SIGRTMAX in libc are safe Rust functions that wrap the C macros.
    let rt_min = libc::SIGRTMIN();
    let rt_max = libc::SIGRTMAX();
    if rt_min > 0 && rt_max >= rt_min {
        for n in rt_min..=rt_max {
            let offset = n - rt_min;
            let name = if offset == 0 {
                "SIGRTMIN".to_string()
            } else if n == rt_max {
                "SIGRTMAX".to_string()
            } else if n > rt_min + (rt_max - rt_min) / 2 {
                format!("SIGRTMAX-{}", rt_max - n)
            } else {
                format!("SIGRTMIN+{}", offset)
            };
            let desc = if offset < 3 {
                "real-time signal (lower offsets often reserved by libc / NPTL)".to_string()
            } else {
                "real-time signal (queueable, application-defined)".to_string()
            };
            out.push(SignalEntry { num: n, name, desc });
        }
    }
    out
}

pub struct SignalSendState {
    pub entries: Vec<SignalEntry>,
    pub view: Vec<usize>,
    pub selected: usize,
    pub filter: String,
    pub editing_filter: bool,
}

impl SignalSendState {
    pub fn new() -> Self {
        let entries = all_signals();
        let mut s = SignalSendState {
            entries,
            view: Vec::new(),
            selected: 0,
            filter: String::new(),
            editing_filter: false,
        };
        s.rebuild_view();
        s
    }

    pub fn rebuild_view(&mut self) {
        let q = self.filter.to_ascii_lowercase();
        self.view = (0..self.entries.len())
            .filter(|&i| {
                if q.is_empty() {
                    return true;
                }
                let e = &self.entries[i];
                e.name.to_ascii_lowercase().contains(&q)
                    || e.desc.to_ascii_lowercase().contains(&q)
                    || e.num.to_string().contains(&q)
            })
            .collect();
        if self.selected >= self.view.len() {
            self.selected = self.view.len().saturating_sub(1);
        }
    }

    pub fn current(&self) -> Option<&SignalEntry> {
        self.view.get(self.selected).map(|&i| &self.entries[i])
    }

    pub fn move_cursor(&mut self, delta: i32) {
        if self.view.is_empty() {
            self.selected = 0;
            return;
        }
        let n = self.view.len() as i32;
        let s = (self.selected as i32 + delta).clamp(0, n - 1);
        self.selected = s as usize;
    }
}

pub struct App {
    pub pid: i32,
    pub attached: bool,
    pub user: UserInfo,
    pub summary: ProcSummary,
    pub screen: Screen,
    pub signals: SignalSendState,
    pub picker: PickerState,
    pub menu_selected: usize,
    pub maps: MapsState,
    pub threads: Vec<ThreadEntry>,
    pub tree: Vec<TreeRow>,
    pub tree_selected: usize,
    pub fds: Vec<FdEntry>,
    pub sockets: HashMap<u64, SocketInfo>,
    pub capabilities: Capabilities,
    pub namespaces: Option<Namespaces>,
    pub security: Option<SecurityInfo>,
    pub limits: String,
    pub limits_scroll: ScrollState,
    pub cgroup_scroll: ScrollState,
    pub environ_scroll: ScrollState,
    pub threads_scroll: ScrollState,
    pub fds_scroll: ScrollState,
    pub caps_scroll: ScrollState,
    pub environ: Vec<(String, String)>,
    pub cgroup_resources: Vec<CgroupSection>,
    pub kstack_threads: Vec<ThreadStack>,
    /// User pressed `w` to collapse each stack to its bottom frame (wchan).
    pub kstack_show_wchan: bool,
    /// User pressed `t` to sweep all threads in /proc/<pid>/task/* instead of
    /// just the main thread (/proc/<pid>/stack).
    pub kstack_all_threads: bool,
    pub kstack_scroll: ScrollState,
    pub strace: Option<StraceSession>,
    pub strace_err: Option<String>,
    pub strace_paused: bool,
    pub strace_scroll: usize, // 0 = follow tail
    pub show_help: bool,
    pub status: String,
    /// htop-style "Z" toggle: when true, the auto-refresh ticker won't
    /// re-read /proc, so views that move (picker, threads) stay still while
    /// the user clicks around. Manual R refresh still works.
    pub frozen: bool,
    /// Render loop only repaints when this is set. Avoids ~5 Hz background
    /// redraws that produce identical frames (and burn allocations for it).
    /// Set on: startup, auto-tick, key/mouse event. Force-on for the strace
    /// screen since its data lands from a background thread.
    pub dirty: bool,
    /// Inner height of the body region after the last render. Set by the UI
    /// layer so the key handlers can clamp scroll offsets without re-deriving
    /// the layout.
    pub body_inner_height: u16,
    /// Top-left y of the body region, set by the UI layer each frame so the
    /// mouse handler can translate click rows into list/table indices.
    pub body_y: u16,
}

impl App {
    pub fn new(initial_pid: Option<i32>) -> Result<Self> {
        let user = current_user();
        let mut app = App {
            pid: 0,
            attached: false,
            user,
            summary: ProcSummary::default(),
            screen: Screen::Picker,
            signals: SignalSendState::new(),
            picker: PickerState::new(),
            menu_selected: 1, // skip "Switch process" at index 0 by default
            maps: MapsState::new(Vec::new(), Vec::new()),
            threads: Vec::new(),
            tree: Vec::new(),
            tree_selected: 0,
            fds: Vec::new(),
            sockets: HashMap::new(),
            capabilities: Capabilities::default(),
            namespaces: None,
            security: None,
            limits: String::new(),
            limits_scroll: ScrollState::default(),
            cgroup_scroll: ScrollState::default(),
            environ_scroll: ScrollState::default(),
            threads_scroll: ScrollState::default(),
            fds_scroll: ScrollState::default(),
            caps_scroll: ScrollState::default(),
            environ: Vec::new(),
            cgroup_resources: Vec::new(),
            kstack_threads: Vec::new(),
            kstack_show_wchan: false,
            kstack_all_threads: false,
            kstack_scroll: ScrollState::default(),
            strace: None,
            strace_err: None,
            strace_paused: false,
            strace_scroll: 0,
            show_help: false,
            status: String::new(),
            frozen: false,
            dirty: true,
            body_inner_height: 0,
            body_y: 0,
        };
        if let Some(pid) = initial_pid {
            app.attach(pid)?;
            app.screen = Screen::Menu;
        }
        Ok(app)
    }

    pub fn attach(&mut self, pid: i32) -> Result<()> {
        self.pid = pid;
        self.summary = ProcSummary::collect(pid)?;
        let mappings = load_mappings(pid)?;
        let annotations = annotate_all(&mappings, &self.summary.info);
        self.maps = MapsState::new(mappings, annotations);
        self.attached = true;
        // Discard any state from a previous attachment.
        self.threads.clear();
        self.fds.clear();
        self.sockets.clear();
        self.capabilities = Capabilities::default();
        self.namespaces = None;
        self.security = None;
        self.limits.clear();
        self.environ.clear();
        self.cgroup_resources.clear();
        self.tree.clear();
        self.tree_selected = 0;
        self.kstack_threads.clear();
        self.kstack_scroll = ScrollState::default();
        self.strace = None;
        self.strace_err = None;
        self.status = format!("attached to pid {pid}");
        Ok(())
    }

    /// Called every ~1s by the event loop. Refreshes the persistent header
    /// (when attached) and the body of screens whose data changes over time.
    /// Respects the `frozen` flag. When frozen, only the header animates
    /// (and even that stops in picker mode, since the picker IS the body).
    pub fn auto_tick(&mut self) {
        // Even if frozen, mark dirty so a one-shot R refresh (which also
        // calls into this path) repaints.
        self.dirty = true;
        if self.attached
            && let Err(e) = self.summary.refresh(self.pid) {
                self.status = format!("summary refresh failed: {e}");
            }
        if self.frozen {
            return;
        }
        let live = matches!(
            self.screen,
            Screen::Picker
                | Screen::Threads
                | Screen::Fds
                | Screen::Cgroup
                | Screen::KernelStack
                | Screen::Tree
                | Screen::Capabilities
                | Screen::Namespaces
                | Screen::Security
        );
        if live {
            let _ = self.refresh_active();
        }
    }

    /// Send the currently highlighted signal in the SignalSend screen. Stays
    /// on the screen so the user can send another and see the result.
    pub fn signals_send_selected(&mut self) {
        let Some(entry) = self.signals.current() else {
            return;
        };
        let pid = self.pid;
        let num = entry.num;
        let name = entry.name.clone();
        // SAFETY: kill(2) with a positive pid and a valid signal number is a
        // straightforward syscall with no memory-safety implications. The
        // kernel rejects invalid pids/signals with errno.
        let rc = unsafe { libc::kill(pid, num) };
        if rc == 0 {
            self.status = format!("Sent {name} (signal {num}) to pid {pid}.");
        } else {
            let err = std::io::Error::last_os_error();
            self.status = format!("Failed to send {name} to pid {pid}: {err}");
        }
    }

    /// Toggle the bottom-frame-only ("wchan") rendering mode for the Kernel
    /// Stack screen. Same underlying data, just a denser view.
    pub fn kstack_toggle_wchan(&mut self) {
        self.kstack_show_wchan = !self.kstack_show_wchan;
        self.kstack_scroll = ScrollState::default();
        self.status = if self.kstack_show_wchan {
            "Kernel stack: wchan mode (bottom frame only).".into()
        } else {
            "Kernel stack: full stack mode.".into()
        };
    }

    /// Toggle between main-thread-only and all-threads sweeps. Triggers an
    /// immediate refresh so the new mode renders without waiting for the tick.
    pub fn kstack_toggle_all_threads(&mut self) {
        self.kstack_all_threads = !self.kstack_all_threads;
        self.kstack_scroll = ScrollState::default();
        self.refresh_kstack();
        self.status = if self.kstack_all_threads {
            "Kernel stack: all threads.".into()
        } else {
            "Kernel stack: main thread only.".into()
        };
    }

    /// Populate `kstack_threads`. In main-only mode this is one entry built
    /// from /proc/<pid>/stack. In all-threads mode we readdir /proc/<pid>/task
    /// (via read_threads, which also gives us state + name) and read each
    /// task's stack file. Per-thread errors are stashed on the entry so the
    /// UI can show "(permission denied)" inline instead of failing the whole
    /// view.
    pub fn refresh_kstack(&mut self) {
        if self.kstack_all_threads {
            let entries = read_threads(self.pid).unwrap_or_default();
            self.kstack_threads = entries
                .into_iter()
                .map(|t| {
                    let (stack, err) = match read_kstack_tid(self.pid, t.tid) {
                        Ok(s) => (Some(s), None),
                        Err(e) => (None, Some(format!("{e}"))),
                    };
                    ThreadStack {
                        tid: t.tid,
                        name: t.name,
                        state: t.state,
                        stack,
                        err,
                    }
                })
                .collect();
        } else {
            let (stack, err) = match read_kstack(self.pid) {
                Ok(s) => (Some(s), None),
                Err(e) => (None, Some(format!("{e}"))),
            };
            self.kstack_threads = vec![ThreadStack {
                tid: self.pid,
                name: self.summary.info.name.clone(),
                state: String::new(),
                stack,
                err,
            }];
        }
    }

    /// Conservative line count for the Kernel Stack screen's scroll clamp.
    /// Mirrors the rendering logic in ui::build_*_lines so the scroller never
    /// scrolls past the last visible row. Overestimating is harmless;
    /// underestimating cuts off the bottom of the view, so prefer the upper
    /// bound when in doubt.
    pub fn kstack_total_lines(&self) -> usize {
        if self.kstack_show_wchan {
            return self.kstack_threads.len();
        }
        let multi = self.kstack_all_threads;
        let mut total = 0;
        for (i, t) in self.kstack_threads.iter().enumerate() {
            if multi {
                if i > 0 {
                    total += 1;
                }
                total += 1;
            }
            if t.err.is_some() {
                total += 1;
            } else if let Some(stack) = &t.stack {
                total += stack.lines().filter(|l| !l.trim().is_empty()).count();
            }
        }
        total
    }

    pub fn toggle_freeze(&mut self) {
        self.frozen = !self.frozen;
        self.status = if self.frozen {
            "Frozen. Auto-refresh paused (Z to resume).".into()
        } else {
            "Live. Auto-refresh resumed.".into()
        };
    }

    pub fn refresh_active(&mut self) -> Result<()> {
        match self.screen {
            Screen::Picker => {
                self.picker.refresh();
            }
            Screen::Maps => {
                let prev = self.maps.current_mapping().map(|m| m.line.start);
                let mappings = load_mappings(self.pid)?;
                let annotations = annotate_all(&mappings, &self.summary.info);
                let mut next = MapsState::new(mappings, annotations);
                if let Some(start) = prev
                    && let Some(pos) = next
                        .view
                        .iter()
                        .position(|&i| next.mappings[i].line.start == start)
                    {
                        next.selected = pos;
                    }
                self.maps = next;
            }
            Screen::Threads => {
                self.threads = read_threads(self.pid)?;
            }
            Screen::Tree => {
                let prev_pid = self
                    .tree
                    .get(self.tree_selected)
                    .map(|r| r.pid);
                self.tree = read_process_tree(self.pid);
                // Preserve the selected pid across refreshes when possible.
                if let Some(pid) = prev_pid {
                    if let Some(pos) = self.tree.iter().position(|r| r.pid == pid) {
                        self.tree_selected = pos;
                    } else if self.tree_selected >= self.tree.len() {
                        self.tree_selected = self.tree.len().saturating_sub(1);
                    }
                } else if self.tree_selected >= self.tree.len() {
                    self.tree_selected = 0;
                }
            }
            Screen::Fds => {
                self.fds = read_fds(self.pid)?;
                // Join socket inodes to endpoint info so we can decorate
                // `socket:[N]` symlinks with real proto/local/remote.
                self.sockets = read_socket_table(self.pid);
            }
            Screen::Capabilities => {
                self.capabilities = read_capabilities(self.pid)?;
            }
            Screen::Namespaces => {
                self.namespaces = Some(read_namespaces(self.pid));
            }
            Screen::Security => {
                self.security = Some(read_security(self.pid));
            }
            Screen::Limits => {
                self.limits = read_limits(self.pid)?;
            }
            Screen::Cgroup => {
                self.summary.cgroup = read_cgroup(self.pid).unwrap_or_default();
                let path = self.summary.cgroup_path();
                self.cgroup_resources = if path.is_empty() {
                    Vec::new()
                } else {
                    read_cgroup_v2_resources(&path)
                };
            }
            Screen::Environ => {
                self.environ = read_environ(self.pid)?;
            }
            Screen::KernelStack => {
                self.refresh_kstack();
            }
            // These screens hold no periodically-refreshed body state.
            Screen::Syscalls | Screen::Menu | Screen::SignalSend => {}
        }
        Ok(())
    }

    pub fn enter_screen(&mut self, s: Screen) {
        // Leaving any screen that started a long-running side-effect (strace)
        // must clean up; do it before switching.
        if self.screen == Screen::Syscalls && s != Screen::Syscalls {
            self.strace = None;
            self.strace_err = None;
        }
        self.screen = s;
        let _ = self.refresh_active();
        if s == Screen::Syscalls && self.strace.is_none() {
            match StraceSession::start(self.pid) {
                Ok(sess) => {
                    self.strace = Some(sess);
                    self.strace_err = None;
                    self.strace_paused = false;
                    self.strace_scroll = 0;
                }
                Err(e) => {
                    self.strace_err = Some(format!("{e}"));
                }
            }
        }
    }

    pub fn back_to_menu(&mut self) {
        // Stopping strace when leaving avoids a runaway tracer if the user
        // wanders off to another screen and forgets.
        self.strace = None;
        self.strace_err = None;
        // Without an attached process there's no menu to go back to.
        if self.attached {
            self.screen = Screen::Menu;
        } else {
            self.screen = Screen::Picker;
        }
    }

    pub fn picker_select(&mut self) {
        let Some(entry) = self.picker.current() else {
            return;
        };
        let pid = entry.pid;
        match self.attach(pid) {
            Ok(()) => {
                self.screen = Screen::Menu;
                self.menu_selected = 1;
            }
            Err(e) => {
                self.status = format!("could not attach to pid {pid}: {e}");
            }
        }
    }

    pub fn current_menu_item(&self) -> &MenuItem {
        &MENU_ITEMS[self.menu_selected.min(MENU_ITEMS.len() - 1)]
    }

    pub fn menu_move(&mut self, delta: i32) {
        let n = MENU_ITEMS.len() as i32;
        if n == 0 {
            return;
        }
        // rem_euclid wraps in both directions: -1 maps to n-1, n maps to 0.
        self.menu_selected = (self.menu_selected as i32 + delta).rem_euclid(n) as usize;
    }

    pub fn menu_enter(&mut self) {
        let item = &MENU_ITEMS[self.menu_selected];
        if item.needs_root && !self.user.is_root {
            self.status = format!("{} needs root.", item.label);
            return;
        }
        if item.screen == Screen::Picker {
            self.menu_enter_picker();
            return;
        }
        self.enter_screen(item.screen);
    }

    /// Re-attach to the pid currently highlighted in the tree view. The
    /// previous process is detached and the menu rebuilds for the new pid.
    pub fn tree_attach_selected(&mut self) {
        let Some(row) = self.tree.get(self.tree_selected) else {
            return;
        };
        if row.pid == self.pid {
            self.status = "Already attached to this pid.".into();
            return;
        }
        let pid = row.pid;
        match self.attach(pid) {
            Ok(()) => {
                self.screen = Screen::Menu;
                self.menu_selected = 1;
            }
            Err(e) => {
                self.status = format!("could not attach to pid {pid}: {e}");
            }
        }
    }

    pub fn tree_move(&mut self, delta: i32) {
        if self.tree.is_empty() {
            self.tree_selected = 0;
            return;
        }
        let n = self.tree.len() as i32;
        let s = (self.tree_selected as i32 + delta).clamp(0, n - 1);
        self.tree_selected = s as usize;
    }

    pub fn menu_enter_picker(&mut self) {
        self.attached = false;
        self.strace = None;
        self.strace_err = None;
        self.picker.refresh();
        self.screen = Screen::Picker;
    }
}

fn category_rank(c: Category) -> u8 {
    match c {
        Category::Exe => 0,
        Category::ExeData => 1,
        Category::LibText => 2,
        Category::LibRodata => 3,
        Category::LibRelro => 4,
        Category::LibData => 5,
        Category::Heap => 6,
        Category::MainStack => 7,
        Category::ThreadStack => 8,
        Category::GuardPage => 9,
        Category::AnonPrivate => 10,
        Category::AnonShared => 11,
        Category::Memfd => 12,
        Category::Shm => 13,
        Category::LocaleData => 14,
        Category::FileMapping => 15,
        Category::Vdso => 16,
        Category::Vvar => 17,
        Category::Vsyscall => 18,
        Category::KernelSpecial => 19,
        Category::Deleted => 20,
        Category::Unknown => 21,
    }
}
