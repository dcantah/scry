use anyhow::{Context, Result, anyhow};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Linux clock tick rate. Overwhelmingly 100 on modern kernels. We treat it
/// as a constant rather than calling sysconf(_SC_CLK_TCK) to avoid pulling in
/// libc just for this one value.
pub const CLK_TCK: u64 = 100;

#[derive(Debug, Clone)]
pub struct MapsLine {
    pub start: u64,
    pub end: u64,
    pub perms: Perms,
    pub offset: u64,
    pub dev: String,
    pub inode: u64,
    pub path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Perms {
    pub r: bool,
    pub w: bool,
    pub x: bool,
    pub shared: bool,
}

impl Perms {
    pub fn render(self) -> String {
        format!(
            "{}{}{}{}",
            if self.r { 'r' } else { '-' },
            if self.w { 'w' } else { '-' },
            if self.x { 'x' } else { '-' },
            if self.shared { 's' } else { 'p' },
        )
    }
}

#[derive(Debug, Clone, Default)]
pub struct SmapsExtra {
    pub size_kb: u64,
    pub rss_kb: u64,
    pub pss_kb: u64,
    pub shared_clean_kb: u64,
    pub shared_dirty_kb: u64,
    pub private_clean_kb: u64,
    pub private_dirty_kb: u64,
    pub anonymous_kb: u64,
    pub swap_kb: u64,
    pub swap_pss_kb: u64,
    pub locked_kb: u64,
    pub referenced_kb: u64,
    pub anon_huge_pages_kb: u64,
    pub kernel_page_size_kb: u64,
    pub mmu_page_size_kb: u64,
    pub thp_eligible: bool,
    pub vm_flags: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Mapping {
    pub line: MapsLine,
    pub smaps: SmapsExtra,
}

impl Mapping {
    pub fn size(&self) -> u64 {
        self.line.end - self.line.start
    }
}

#[derive(Debug, Clone, Default)]
pub struct ProcInfo {
    pub pid: i32,
    pub name: String,
    pub cmdline: String,
    pub state: String,
    pub vm_size_kb: u64,
    pub vm_rss_kb: u64,
    pub vm_data_kb: u64,
    pub vm_stk_kb: u64,
    pub vm_exe_kb: u64,
    pub vm_lib_kb: u64,
    pub threads: u64,
    pub exe_path: Option<PathBuf>,
}

pub fn parse_perms(s: &str) -> Result<Perms> {
    let b = s.as_bytes();
    if b.len() < 4 {
        return Err(anyhow!("perms too short: {s}"));
    }
    Ok(Perms {
        r: b[0] == b'r',
        w: b[1] == b'w',
        x: b[2] == b'x',
        shared: b[3] == b's',
    })
}

pub fn parse_maps_line(s: &str) -> Result<MapsLine> {
    // Format: addr_start-addr_end perms offset dev inode path
    let mut it = s.splitn(6, ' ').filter(|x| !x.is_empty());
    let range = it.next().ok_or_else(|| anyhow!("missing range"))?;
    let perms = it.next().ok_or_else(|| anyhow!("missing perms"))?;
    let offset = it.next().ok_or_else(|| anyhow!("missing offset"))?;
    let dev = it.next().ok_or_else(|| anyhow!("missing dev"))?;
    let inode = it.next().ok_or_else(|| anyhow!("missing inode"))?;
    let path = it.next().unwrap_or("").trim().to_string();

    let (start_s, end_s) = range
        .split_once('-')
        .ok_or_else(|| anyhow!("bad range: {range}"))?;
    let start = u64::from_str_radix(start_s, 16)?;
    let end = u64::from_str_radix(end_s, 16)?;
    let offset = u64::from_str_radix(offset, 16)?;
    let inode: u64 = inode.parse()?;

    Ok(MapsLine {
        start,
        end,
        perms: parse_perms(perms)?,
        offset,
        dev: dev.to_string(),
        inode,
        path,
    })
}

fn parse_kb(value: &str) -> u64 {
    // Lines look like "Rss:                   8 kB"
    value
        .split_whitespace().next()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0)
}

pub fn load_mappings(pid: i32) -> Result<Vec<Mapping>> {
    let smaps_path = format!("/proc/{pid}/smaps");
    let smaps =
        fs::read_to_string(&smaps_path).with_context(|| format!("reading {smaps_path}"))?;
    parse_smaps(&smaps)
}

pub fn parse_smaps(text: &str) -> Result<Vec<Mapping>> {
    let mut out: Vec<Mapping> = Vec::new();
    let mut cur: Option<Mapping> = None;
    for raw in text.lines() {
        // A maps header line is "<hex>-<hex> ...". Match that shape rather than
        // just "first byte is hex", since smaps keys like "Anonymous:" also start
        // with a hex digit.
        let first_tok = raw.split_whitespace().next().unwrap_or("");
        let is_header = first_tok
            .split_once('-')
            .map(|(a, b)| !a.is_empty()
                && !b.is_empty()
                && a.bytes().all(|c| c.is_ascii_hexdigit())
                && b.bytes().all(|c| c.is_ascii_hexdigit()))
            .unwrap_or(false);
        if is_header {
            if let Some(m) = cur.take() {
                out.push(m);
            }
            let line = parse_maps_line(raw)?;
            cur = Some(Mapping {
                line,
                smaps: SmapsExtra::default(),
            });
            continue;
        }
        let Some(m) = cur.as_mut() else { continue };
        let Some((k, v)) = raw.split_once(':') else {
            continue;
        };
        let v = v.trim();
        match k {
            "Size" => m.smaps.size_kb = parse_kb(v),
            "Rss" => m.smaps.rss_kb = parse_kb(v),
            "Pss" => m.smaps.pss_kb = parse_kb(v),
            "Shared_Clean" => m.smaps.shared_clean_kb = parse_kb(v),
            "Shared_Dirty" => m.smaps.shared_dirty_kb = parse_kb(v),
            "Private_Clean" => m.smaps.private_clean_kb = parse_kb(v),
            "Private_Dirty" => m.smaps.private_dirty_kb = parse_kb(v),
            "Anonymous" => m.smaps.anonymous_kb = parse_kb(v),
            "Swap" => m.smaps.swap_kb = parse_kb(v),
            "SwapPss" => m.smaps.swap_pss_kb = parse_kb(v),
            "Locked" => m.smaps.locked_kb = parse_kb(v),
            "Referenced" => m.smaps.referenced_kb = parse_kb(v),
            "AnonHugePages" => m.smaps.anon_huge_pages_kb = parse_kb(v),
            "KernelPageSize" => m.smaps.kernel_page_size_kb = parse_kb(v),
            "MMUPageSize" => m.smaps.mmu_page_size_kb = parse_kb(v),
            "THPeligible" => m.smaps.thp_eligible = v.starts_with('1'),
            "VmFlags" => {
                m.smaps.vm_flags = v.split_whitespace().map(|s| s.to_string()).collect();
            }
            _ => {}
        }
    }
    if let Some(m) = cur.take() {
        out.push(m);
    }
    Ok(out)
}

pub fn load_proc_info(pid: i32) -> Result<ProcInfo> {
    let mut info = ProcInfo {
        pid,
        ..Default::default()
    };

    let status_path = format!("/proc/{pid}/status");
    let status =
        fs::read_to_string(&status_path).with_context(|| format!("reading {status_path}"))?;
    let mut kv: HashMap<&str, &str> = HashMap::new();
    for line in status.lines() {
        if let Some((k, v)) = line.split_once(':') {
            kv.insert(k, v.trim());
        }
    }
    info.name = kv.get("Name").copied().unwrap_or("").to_string();
    info.state = kv.get("State").copied().unwrap_or("").to_string();
    info.vm_size_kb = kv.get("VmSize").map(|v| parse_kb(v)).unwrap_or(0);
    info.vm_rss_kb = kv.get("VmRSS").map(|v| parse_kb(v)).unwrap_or(0);
    info.vm_data_kb = kv.get("VmData").map(|v| parse_kb(v)).unwrap_or(0);
    info.vm_stk_kb = kv.get("VmStk").map(|v| parse_kb(v)).unwrap_or(0);
    info.vm_exe_kb = kv.get("VmExe").map(|v| parse_kb(v)).unwrap_or(0);
    info.vm_lib_kb = kv.get("VmLib").map(|v| parse_kb(v)).unwrap_or(0);
    info.threads = kv
        .get("Threads")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    let cmdline_path = format!("/proc/{pid}/cmdline");
    if let Ok(raw) = fs::read(&cmdline_path) {
        // arguments are NUL separated, terminate with NUL
        let s: String = raw
            .split(|&b| b == 0)
            .filter(|b| !b.is_empty())
            .map(|b| String::from_utf8_lossy(b).to_string())
            .collect::<Vec<_>>()
            .join(" ");
        info.cmdline = s;
    }

    let exe = Path::new("/proc").join(pid.to_string()).join("exe");
    info.exe_path = fs::read_link(&exe).ok();

    Ok(info)
}

// ---------------------------------------------------------------------------
// Extended /proc readers used by the various views
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
#[allow(dead_code)] // pid/comm/etc. surface on demand; keep parsed for future views.
pub struct ProcStat {
    pub pid: i32,
    pub comm: String,
    pub state: char,
    pub ppid: i32,
    pub priority: i64,
    pub nice: i64,
    pub num_threads: i64,
    pub starttime_ticks: u64,
    pub utime_ticks: u64,
    pub stime_ticks: u64,
    pub vsize: u64,
    pub rss_pages: u64,
    pub minflt: u64,
    pub majflt: u64,
}

pub fn read_stat(pid: i32) -> Result<ProcStat> {
    let path = format!("/proc/{pid}/stat");
    let raw = fs::read_to_string(&path).with_context(|| format!("reading {path}"))?;
    let close = raw
        .rfind(')')
        .ok_or_else(|| anyhow!("malformed /proc/{pid}/stat"))?;
    let comm = raw
        .find('(')
        .map(|open| raw[open + 1..close].to_string())
        .unwrap_or_default();
    let after = raw[close + 1..].trim();
    let f: Vec<&str> = after.split_whitespace().collect();
    // 0:state 1:ppid 2:pgrp 3:session 4:tty_nr 5:tpgid 6:flags
    // 7:minflt 8:cminflt 9:majflt 10:cmajflt 11:utime 12:stime
    // 13:cutime 14:cstime 15:priority 16:nice 17:num_threads 18:itrealvalue
    // 19:starttime 20:vsize 21:rss
    let g = |i: usize| f.get(i).copied().unwrap_or("0");
    Ok(ProcStat {
        pid,
        comm,
        state: g(0).chars().next().unwrap_or('?'),
        ppid: g(1).parse().unwrap_or(0),
        minflt: g(7).parse().unwrap_or(0),
        majflt: g(9).parse().unwrap_or(0),
        utime_ticks: g(11).parse().unwrap_or(0),
        stime_ticks: g(12).parse().unwrap_or(0),
        priority: g(15).parse().unwrap_or(0),
        nice: g(16).parse().unwrap_or(0),
        num_threads: g(17).parse().unwrap_or(0),
        starttime_ticks: g(19).parse().unwrap_or(0),
        vsize: g(20).parse().unwrap_or(0),
        rss_pages: g(21).parse().unwrap_or(0),
    })
}

pub fn read_io(pid: i32) -> Result<HashMap<String, u64>> {
    let path = format!("/proc/{pid}/io");
    let raw = fs::read_to_string(&path).with_context(|| format!("reading {path}"))?;
    let mut out = HashMap::new();
    for line in raw.lines() {
        if let Some((k, v)) = line.split_once(':')
            && let Ok(n) = v.trim().parse() {
                out.insert(k.to_string(), n);
            }
    }
    Ok(out)
}

pub fn read_limits(pid: i32) -> Result<String> {
    let path = format!("/proc/{pid}/limits");
    fs::read_to_string(&path).with_context(|| format!("reading {path}"))
}

/// Pretty bytes (e.g. 1.2 MB). Used by both the UI and the cgroup pre-formatter.
pub fn fmt_bytes(b: u64) -> String {
    if b >= 1024 * 1024 * 1024 {
        format!("{:.1} GB", b as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if b >= 1024 * 1024 {
        format!("{:.1} MB", b as f64 / (1024.0 * 1024.0))
    } else if b >= 1024 {
        format!("{:.1} KB", b as f64 / 1024.0)
    } else {
        format!("{b} B")
    }
}

#[derive(Debug, Clone)]
pub struct CgroupSection {
    pub heading: &'static str,
    pub entries: Vec<(String, String)>,
}

/// Read cgroup v2 resource files under /sys/fs/cgroup<cgroup_path> and return
/// human-readable sections (Memory, CPU, Cpuset, PIDs, IO, Controllers).
///
/// Each file is best-effort: missing files just produce no entries, so the
/// caller can tolerate slim cgroups (like /init.scope on a default systemd
/// install where only cgroup.* exist).
pub fn read_cgroup_v2_resources(cgroup_path: &str) -> Vec<CgroupSection> {
    let base: PathBuf =
        PathBuf::from("/sys/fs/cgroup").join(cgroup_path.trim_start_matches('/'));
    let read = |name: &str| -> Option<String> {
        fs::read_to_string(base.join(name))
            .ok()
            .map(|s| s.trim().to_string())
    };

    let fmt_size = |raw: &str| -> String {
        if raw == "max" {
            return "max (unlimited)".to_string();
        }
        if let Ok(b) = raw.parse::<u64>() {
            return format!("{} ({} B)", fmt_bytes(b), b);
        }
        raw.to_string()
    };

    let fmt_cpu_max = |raw: &str| -> String {
        // Format: "max 100000" (unlimited) or "<quota_us> <period_us>".
        let parts: Vec<&str> = raw.split_whitespace().collect();
        if parts.len() == 2 {
            if parts[0] == "max" {
                return format!("unlimited (period {} μs)", parts[1]);
            }
            let q: f64 = parts[0].parse().unwrap_or(0.0);
            let p: f64 = parts[1].parse().unwrap_or(1.0);
            return format!(
                "{} μs / {} μs   ≈ {:.2} CPU",
                parts[0],
                parts[1],
                if p > 0.0 { q / p } else { 0.0 }
            );
        }
        raw.to_string()
    };

    let mut sections: Vec<CgroupSection> = Vec::new();

    // Memory
    let mut entries: Vec<(String, String)> = Vec::new();
    for name in [
        "memory.current",
        "memory.max",
        "memory.high",
        "memory.low",
        "memory.min",
        "memory.swap.current",
        "memory.swap.max",
        "memory.peak",
    ] {
        if let Some(v) = read(name) {
            entries.push((name.into(), fmt_size(&v)));
        }
    }
    if !entries.is_empty() {
        sections.push(CgroupSection {
            heading: "Memory",
            entries,
        });
    }

    // CPU
    let mut entries: Vec<(String, String)> = Vec::new();
    if let Some(v) = read("cpu.max") {
        entries.push(("cpu.max".into(), fmt_cpu_max(&v)));
    }
    if let Some(v) = read("cpu.max.burst") {
        entries.push(("cpu.max.burst".into(), v));
    }
    if let Some(v) = read("cpu.weight") {
        entries.push(("cpu.weight".into(), v));
    }
    if let Some(v) = read("cpu.weight.nice") {
        entries.push(("cpu.weight.nice".into(), v));
    }
    if let Some(v) = read("cpu.idle") {
        entries.push(("cpu.idle".into(), v));
    }
    if let Some(v) = read("cpu.stat") {
        for l in v.lines() {
            if let Some((k, val)) = l.split_once(' ') {
                entries.push((format!("cpu.stat.{k}"), val.to_string()));
            }
        }
    }
    if !entries.is_empty() {
        sections.push(CgroupSection {
            heading: "CPU",
            entries,
        });
    }

    // Cpuset
    let mut entries: Vec<(String, String)> = Vec::new();
    for name in [
        "cpuset.cpus",
        "cpuset.cpus.effective",
        "cpuset.mems",
        "cpuset.mems.effective",
        "cpuset.cpus.partition",
    ] {
        if let Some(v) = read(name) {
            let pretty = if v.is_empty() {
                "(inherited)".to_string()
            } else {
                v
            };
            entries.push((name.into(), pretty));
        }
    }
    if !entries.is_empty() {
        sections.push(CgroupSection {
            heading: "Cpuset",
            entries,
        });
    }

    // PIDs
    let mut entries: Vec<(String, String)> = Vec::new();
    for name in ["pids.current", "pids.max", "pids.peak"] {
        if let Some(v) = read(name) {
            entries.push((name.into(), v));
        }
    }
    if !entries.is_empty() {
        sections.push(CgroupSection {
            heading: "PIDs",
            entries,
        });
    }

    // IO
    let mut entries: Vec<(String, String)> = Vec::new();
    if let Some(v) = read("io.max") {
        if v.is_empty() {
            entries.push(("io.max".into(), "(no per-device limits)".into()));
        } else {
            for line in v.lines() {
                entries.push(("io.max".into(), line.to_string()));
            }
        }
    }
    if let Some(v) = read("io.weight") {
        entries.push(("io.weight".into(), v));
    }
    if let Some(v) = read("io.latency")
        && !v.is_empty() {
            for line in v.lines() {
                entries.push(("io.latency".into(), line.to_string()));
            }
        }
    if !entries.is_empty() {
        sections.push(CgroupSection {
            heading: "IO",
            entries,
        });
    }

    // Controllers
    let mut entries: Vec<(String, String)> = Vec::new();
    if let Some(v) = read("cgroup.controllers") {
        entries.push((
            "controllers (active here)".into(),
            if v.is_empty() { "(none)".into() } else { v },
        ));
    }
    if let Some(v) = read("cgroup.subtree_control") {
        entries.push((
            "subtree_control (enabled for children)".into(),
            if v.is_empty() { "(none)".into() } else { v },
        ));
    }
    if let Some(v) = read("cgroup.type") {
        entries.push(("cgroup.type".into(), v));
    }
    if !entries.is_empty() {
        sections.push(CgroupSection {
            heading: "Controllers",
            entries,
        });
    }

    sections
}

pub fn read_cgroup(pid: i32) -> Result<Vec<(String, String, String)>> {
    // Each line: hierarchy_id:controllers:path
    let path = format!("/proc/{pid}/cgroup");
    let raw = fs::read_to_string(&path).with_context(|| format!("reading {path}"))?;
    let mut out = Vec::new();
    for line in raw.lines() {
        let parts: Vec<&str> = line.splitn(3, ':').collect();
        if parts.len() == 3 {
            out.push((parts[0].into(), parts[1].into(), parts[2].into()));
        }
    }
    Ok(out)
}

pub fn read_environ(pid: i32) -> Result<Vec<(String, String)>> {
    let path = format!("/proc/{pid}/environ");
    let raw = fs::read(&path).with_context(|| format!("reading {path}"))?;
    let mut out = Vec::new();
    for entry in raw.split(|&b| b == 0) {
        if entry.is_empty() {
            continue;
        }
        let s = String::from_utf8_lossy(entry);
        if let Some((k, v)) = s.split_once('=') {
            out.push((k.to_string(), v.to_string()));
        } else {
            out.push((s.to_string(), String::new()));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

// ---------------------------------------------------------------------------
// Capabilities (CAP_*) decoding
// ---------------------------------------------------------------------------

/// Bit -> name table for the standard Linux capabilities. Kept in numeric
/// order so the matrix view reads top-to-bottom from CAP_CHOWN onward.
pub const CAP_NAMES: &[&str] = &[
    "CAP_CHOWN",            // 0
    "CAP_DAC_OVERRIDE",     // 1
    "CAP_DAC_READ_SEARCH",  // 2
    "CAP_FOWNER",           // 3
    "CAP_FSETID",           // 4
    "CAP_KILL",             // 5
    "CAP_SETGID",           // 6
    "CAP_SETUID",           // 7
    "CAP_SETPCAP",          // 8
    "CAP_LINUX_IMMUTABLE",  // 9
    "CAP_NET_BIND_SERVICE", // 10
    "CAP_NET_BROADCAST",    // 11
    "CAP_NET_ADMIN",        // 12
    "CAP_NET_RAW",          // 13
    "CAP_IPC_LOCK",         // 14
    "CAP_IPC_OWNER",        // 15
    "CAP_SYS_MODULE",       // 16
    "CAP_SYS_RAWIO",        // 17
    "CAP_SYS_CHROOT",       // 18
    "CAP_SYS_PTRACE",       // 19
    "CAP_SYS_PACCT",        // 20
    "CAP_SYS_ADMIN",        // 21
    "CAP_SYS_BOOT",         // 22
    "CAP_SYS_NICE",         // 23
    "CAP_SYS_RESOURCE",     // 24
    "CAP_SYS_TIME",         // 25
    "CAP_SYS_TTY_CONFIG",   // 26
    "CAP_MKNOD",            // 27
    "CAP_LEASE",            // 28
    "CAP_AUDIT_WRITE",      // 29
    "CAP_AUDIT_CONTROL",    // 30
    "CAP_SETFCAP",          // 31
    "CAP_MAC_OVERRIDE",     // 32
    "CAP_MAC_ADMIN",        // 33
    "CAP_SYSLOG",           // 34
    "CAP_WAKE_ALARM",       // 35
    "CAP_BLOCK_SUSPEND",    // 36
    "CAP_AUDIT_READ",       // 37
    "CAP_PERF_MONITOR",     // 38
    "CAP_BPF",              // 39
    "CAP_CHECKPOINT_RESTORE", // 40
];

#[derive(Debug, Clone, Copy, Default)]
pub struct Capabilities {
    pub inheritable: u64,
    pub permitted: u64,
    pub effective: u64,
    pub bounding: u64,
    pub ambient: u64,
}

pub fn read_capabilities(pid: i32) -> Result<Capabilities> {
    let path = format!("/proc/{pid}/status");
    let raw = fs::read_to_string(&path).with_context(|| format!("reading {path}"))?;
    let mut out = Capabilities::default();
    for line in raw.lines() {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let v = v.trim();
        let parsed = u64::from_str_radix(v, 16).ok();
        match (k, parsed) {
            ("CapInh", Some(n)) => out.inheritable = n,
            ("CapPrm", Some(n)) => out.permitted = n,
            ("CapEff", Some(n)) => out.effective = n,
            ("CapBnd", Some(n)) => out.bounding = n,
            ("CapAmb", Some(n)) => out.ambient = n,
            _ => {}
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Network sockets (joined to fds by inode)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketProto {
    Tcp4,
    Tcp6,
    Udp4,
    Udp6,
    Unix,
}

impl SocketProto {
    pub fn short(self) -> &'static str {
        match self {
            SocketProto::Tcp4 => "TCP",
            SocketProto::Tcp6 => "TCP6",
            SocketProto::Udp4 => "UDP",
            SocketProto::Udp6 => "UDP6",
            SocketProto::Unix => "UNIX",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SocketInfo {
    pub proto: SocketProto,
    pub inode: u64,
    pub local: String,
    pub remote: String,
    pub state: String,
}

fn parse_v4_addr(s: &str) -> Option<String> {
    // "FEFFFF0A:0035" format: 8 hex chars for the address, 4 for the port.
    let (addr, port) = s.split_once(':')?;
    if addr.len() != 8 || port.len() != 4 {
        return None;
    }
    let n = u32::from_str_radix(addr, 16).ok()?;
    let p = u16::from_str_radix(port, 16).ok()?;
    let b = n.to_le_bytes();
    Some(format!("{}.{}.{}.{}:{}", b[0], b[1], b[2], b[3], p))
}

fn parse_v6_addr(s: &str) -> Option<String> {
    // 32 hex chars for the address (four host-order u32 words), then ":port".
    let (addr, port) = s.split_once(':')?;
    if addr.len() != 32 || port.len() != 4 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for word in 0..4 {
        let chunk = &addr[word * 8..word * 8 + 8];
        let n = u32::from_str_radix(chunk, 16).ok()?;
        let le = n.to_le_bytes();
        bytes[word * 4..word * 4 + 4].copy_from_slice(&le);
    }
    let p = u16::from_str_radix(port, 16).ok()?;
    let addr = std::net::Ipv6Addr::from(bytes);
    Some(format!("[{addr}]:{p}"))
}

fn tcp_state(code: &str) -> &'static str {
    match code {
        "01" => "ESTAB",
        "02" => "SYN_SENT",
        "03" => "SYN_RECV",
        "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",
        "06" => "TIME_WAIT",
        "07" => "CLOSE",
        "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",
        "0A" => "LISTEN",
        "0B" => "CLOSING",
        _ => "UNKNOWN",
    }
}

fn unix_state(code: &str) -> &'static str {
    match code {
        "01" => "UNCONN",
        "02" => "CONNECTING",
        "03" => "ESTAB",
        "04" => "DISCONNECTING",
        _ => "?",
    }
}

fn parse_inet_table(
    raw: &str,
    proto: SocketProto,
    parse_addr: fn(&str) -> Option<String>,
    state_decoder: fn(&str) -> &'static str,
    out: &mut HashMap<u64, SocketInfo>,
) {
    for (i, line) in raw.lines().enumerate() {
        if i == 0 {
            continue; // header
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 {
            continue;
        }
        let local = parse_addr(f[1]).unwrap_or_else(|| f[1].to_string());
        let remote = parse_addr(f[2]).unwrap_or_else(|| f[2].to_string());
        let state = state_decoder(f[3]).to_string();
        let Ok(inode) = f[9].parse::<u64>() else { continue };
        if inode == 0 {
            continue;
        }
        out.insert(
            inode,
            SocketInfo {
                proto,
                inode,
                local,
                remote,
                state,
            },
        );
    }
}

fn parse_unix_table(raw: &str, out: &mut HashMap<u64, SocketInfo>) {
    for (i, line) in raw.lines().enumerate() {
        if i == 0 {
            continue; // header
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        // Num RefCount Protocol Flags Type St Inode [Path]
        if f.len() < 7 {
            continue;
        }
        let state = unix_state(f[5]).to_string();
        let Ok(inode) = f[6].parse::<u64>() else { continue };
        if inode == 0 {
            continue;
        }
        let path = f.get(7).copied().unwrap_or("").to_string();
        out.insert(
            inode,
            SocketInfo {
                proto: SocketProto::Unix,
                inode,
                local: if path.is_empty() {
                    "<unnamed>".to_string()
                } else {
                    path
                },
                remote: String::new(),
                state,
            },
        );
    }
}

/// Read the network socket tables visible from the target process's namespace.
/// Returns a map from socket inode to its decoded endpoint info, which the
/// FDs view joins against `socket:[N]` symlink targets.
pub fn read_socket_table(pid: i32) -> HashMap<u64, SocketInfo> {
    let mut out: HashMap<u64, SocketInfo> = HashMap::new();
    let try_read = |name: &str| -> Option<String> {
        fs::read_to_string(format!("/proc/{pid}/net/{name}")).ok()
    };
    if let Some(t) = try_read("tcp") {
        parse_inet_table(&t, SocketProto::Tcp4, parse_v4_addr, tcp_state, &mut out);
    }
    if let Some(t) = try_read("tcp6") {
        parse_inet_table(&t, SocketProto::Tcp6, parse_v6_addr, tcp_state, &mut out);
    }
    if let Some(t) = try_read("udp") {
        parse_inet_table(&t, SocketProto::Udp4, parse_v4_addr, tcp_state, &mut out);
    }
    if let Some(t) = try_read("udp6") {
        parse_inet_table(&t, SocketProto::Udp6, parse_v6_addr, tcp_state, &mut out);
    }
    if let Some(t) = try_read("unix") {
        parse_unix_table(&t, &mut out);
    }
    out
}

// ---------------------------------------------------------------------------
// Namespaces
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct NamespaceEntry {
    pub kind: &'static str,
    pub inode: u64,
    pub raw: String,
}

#[derive(Debug, Clone)]
pub struct Namespaces {
    pub entries: Vec<NamespaceEntry>,
    /// Reference namespaces we compare against. `reference_source` is the
    /// label we show ("init" if we managed to read /proc/1/ns/, "scry"
    /// otherwise).
    pub reference: HashMap<&'static str, u64>,
    pub reference_source: &'static str,
}

const NS_KINDS: &[&str] = &[
    "pid",
    "mnt",
    "net",
    "user",
    "ipc",
    "uts",
    "cgroup",
    "time",
    "pid_for_children",
    "time_for_children",
];

fn parse_ns_inode(s: &str) -> Option<u64> {
    let (_, rest) = s.split_once('[')?;
    let inner = rest.strip_suffix(']')?;
    inner.parse().ok()
}

fn read_ns_link(pid: i32, kind: &str) -> Option<(u64, String)> {
    let target = fs::read_link(format!("/proc/{pid}/ns/{kind}")).ok()?;
    let raw = target.display().to_string();
    let inode = parse_ns_inode(&raw)?;
    Some((inode, raw))
}

fn read_ns_set(pid: i32) -> HashMap<&'static str, u64> {
    let mut out = HashMap::new();
    for k in NS_KINDS {
        if let Some((inode, _)) = read_ns_link(pid, k) {
            out.insert(*k, inode);
        }
    }
    out
}

pub fn read_namespaces(pid: i32) -> Namespaces {
    let entries: Vec<NamespaceEntry> = NS_KINDS
        .iter()
        .filter_map(|k| {
            read_ns_link(pid, k).map(|(inode, raw)| NamespaceEntry {
                kind: k,
                inode,
                raw,
            })
        })
        .collect();

    // Pick the strongest comparison baseline available: init's namespaces if
    // we can read them (root or same user as pid 1), otherwise scry's own.
    let (reference, reference_source) = {
        let init = read_ns_set(1);
        if !init.is_empty() {
            (init, "init")
        } else {
            (read_ns_set(std::process::id() as i32), "scry")
        }
    };

    Namespaces {
        entries,
        reference,
        reference_source,
    }
}

// ---------------------------------------------------------------------------
// Security overview: Seccomp, NoNewPrivs, LSM, Yama
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeccompMode {
    Disabled,
    Strict,
    Filter,
    Unknown(u8),
}

impl SeccompMode {
    pub fn from_raw(n: u8) -> Self {
        match n {
            0 => SeccompMode::Disabled,
            1 => SeccompMode::Strict,
            2 => SeccompMode::Filter,
            other => SeccompMode::Unknown(other),
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            SeccompMode::Disabled => "disabled",
            SeccompMode::Strict => "strict (read/write/_exit/sigreturn only)",
            SeccompMode::Filter => "filter (BPF-based)",
            SeccompMode::Unknown(_) => "unknown",
        }
    }
    pub fn is_active(self) -> bool {
        matches!(self, SeccompMode::Strict | SeccompMode::Filter)
    }
}

#[derive(Debug, Clone)]
pub struct SecurityInfo {
    pub seccomp_mode: SeccompMode,
    /// Number of stacked filters; Linux 5.9+ exposes this. None on older
    /// kernels.
    pub seccomp_filters: Option<u32>,
    pub no_new_privs: bool,
    /// LSM label from /proc/<pid>/attr/current. Empty on systems without a
    /// loaded LSM, "unconfined" for AppArmor non-confined processes, an
    /// AppArmor profile path with mode suffix like
    /// "/usr/bin/firefox (enforce)", or a SELinux context.
    pub lsm_label: Option<String>,
    pub lsm_kind: LsmKind,
    /// System-wide Yama policy. None if the sysctl isn't present.
    pub yama_ptrace_scope: Option<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Smack is a real LSM but we don't currently classify it.
pub enum LsmKind {
    None,
    AppArmor,
    SELinux,
    Smack,
    Unknown,
}

impl LsmKind {
    pub fn label(self) -> &'static str {
        match self {
            LsmKind::None => "none",
            LsmKind::AppArmor => "AppArmor",
            LsmKind::SELinux => "SELinux",
            LsmKind::Smack => "Smack",
            LsmKind::Unknown => "unknown",
        }
    }
}

fn classify_lsm(label: &str) -> LsmKind {
    if label.is_empty() {
        return LsmKind::None;
    }
    // SELinux contexts are colon-separated (user:role:type[:level]), so three
    // or more colons is a reliable tell alongside the common user prefixes.
    if label.starts_with("system_u:")
        || label.starts_with("staff_u:")
        || label.matches(':').count() >= 3
    {
        return LsmKind::SELinux;
    }
    if label == "kernel" || label == "unconfined" || label.contains("(enforce)") || label.contains("(complain)") {
        return LsmKind::AppArmor;
    }
    LsmKind::Unknown
}

pub fn read_security(pid: i32) -> SecurityInfo {
    // status: Seccomp / Seccomp_filters / NoNewPrivs
    let mut seccomp_mode = SeccompMode::Disabled;
    let mut seccomp_filters: Option<u32> = None;
    let mut no_new_privs = false;
    if let Ok(s) = fs::read_to_string(format!("/proc/{pid}/status")) {
        for line in s.lines() {
            let Some((k, v)) = line.split_once(':') else {
                continue;
            };
            let v = v.trim();
            match k {
                "Seccomp" => {
                    if let Ok(n) = v.parse::<u8>() {
                        seccomp_mode = SeccompMode::from_raw(n);
                    }
                }
                "Seccomp_filters" => {
                    seccomp_filters = v.parse().ok();
                }
                "NoNewPrivs" => {
                    no_new_privs = v.starts_with('1');
                }
                _ => {}
            }
        }
    }

    // LSM label: /proc/<pid>/attr/current is NUL-terminated text.
    let lsm_label = fs::read(format!("/proc/{pid}/attr/current")).ok().map(|b| {
        let s = String::from_utf8_lossy(&b);
        s.trim_end_matches(['\0', '\n']).to_string()
    });
    let lsm_kind = lsm_label
        .as_deref()
        .map(classify_lsm)
        .unwrap_or(LsmKind::None);

    // Yama ptrace_scope is system-wide; the file is missing on kernels built
    // without YAMA, in which case treat as None.
    let yama_ptrace_scope = fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .ok()
        .and_then(|s| s.trim().parse().ok());

    SecurityInfo {
        seccomp_mode,
        seccomp_filters,
        no_new_privs,
        lsm_label,
        lsm_kind,
        yama_ptrace_scope,
    }
}

pub fn read_kstack(pid: i32) -> Result<String> {
    let path = format!("/proc/{pid}/stack");
    fs::read_to_string(&path).with_context(|| format!("reading {path}"))
}

pub fn read_kstack_tid(pid: i32, tid: i32) -> Result<String> {
    let path = format!("/proc/{pid}/task/{tid}/stack");
    fs::read_to_string(&path).with_context(|| format!("reading {path}"))
}

/// Pull the "wchan" symbol (the bottom-most kernel frame) out of a
/// `/proc/<pid>/stack` blob. The first non-blank line is the deepest frame
/// (where the task is currently parked). Format is `[<0>] symbol+0xoff/0xsz`.
/// Returns None for empty stacks (the task is on-CPU) or unparseable input.
pub fn extract_wchan(stack: &str) -> Option<&str> {
    let line = stack.lines().find(|l| !l.trim().is_empty())?;
    let after_marker = line.split_once("] ").map(|(_, r)| r).unwrap_or(line);
    let sym = after_marker.split('+').next().unwrap_or(after_marker).trim();
    if sym.is_empty() { None } else { Some(sym) }
}

#[derive(Debug, Clone)]
pub struct FdEntry {
    pub fd: i32,
    pub target: String,
    pub flags: Option<String>,
    pub pos: Option<u64>,
}

/// Count entries in /proc/<pid>/fd without building the full FdEntry list.
/// Used for the persistent header so we don't pay symlink + fdinfo costs on
/// every 1s tick.
pub fn count_fds(pid: i32) -> Option<usize> {
    fs::read_dir(format!("/proc/{pid}/fd"))
        .ok()
        .map(|rd| rd.filter_map(|e| e.ok()).count())
}

pub fn read_fds(pid: i32) -> Result<Vec<FdEntry>> {
    let dir = format!("/proc/{pid}/fd");
    let mut out = Vec::new();
    for entry in fs::read_dir(&dir).with_context(|| format!("reading {dir}"))? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(fd_str) = name.to_str() else { continue };
        let Ok(fd) = fd_str.parse::<i32>() else {
            continue;
        };
        let target = fs::read_link(entry.path())
            .map(|p| p.display().to_string())
            .unwrap_or_else(|e| format!("<{e}>"));
        let info_path = format!("/proc/{pid}/fdinfo/{fd}");
        let (flags, pos) = match fs::read_to_string(&info_path) {
            Ok(t) => {
                let mut flags = None;
                let mut pos = None;
                for l in t.lines() {
                    if let Some(rest) = l.strip_prefix("flags:") {
                        flags = Some(rest.trim().to_string());
                    }
                    if let Some(rest) = l.strip_prefix("pos:") {
                        pos = rest.trim().parse().ok();
                    }
                }
                (flags, pos)
            }
            Err(_) => (None, None),
        };
        out.push(FdEntry {
            fd,
            target,
            flags,
            pos,
        });
    }
    out.sort_by_key(|f| f.fd);
    Ok(out)
}

#[derive(Debug, Clone)]
pub struct ThreadEntry {
    pub tid: i32,
    pub name: String,
    pub state: String,
    pub cpu_ticks: u64,
}

#[derive(Debug, Clone)]
pub struct TreeRow {
    pub pid: i32,
    /// Depth in the tree; the root is 0.
    pub depth: usize,
    /// One entry per ancestor level (depth elements). `true` means the
    /// ancestor at that level was the last child of its parent, so that
    /// column should be blank rather than a continuation pipe.
    pub last_at_depth: Vec<bool>,
    /// Whether this node is the last child of its parent (drives `└─` vs `├─`).
    pub is_last_sibling: bool,
    pub comm: String,
    pub state: char,
    pub threads: i64,
    pub uid: u32,
    pub cmdline: String,
}

/// Walk all of /proc, build a ppid -> children map, then DFS from `root_pid`
/// to produce a flat ordered list of TreeRow with depth + branch markers
/// suitable for direct rendering.
pub fn read_process_tree(root_pid: i32) -> Vec<TreeRow> {
    let mut children: HashMap<i32, Vec<i32>> = HashMap::new();
    let mut stats: HashMap<i32, ProcStat> = HashMap::new();
    for pid in enumerate_pids() {
        if let Ok(s) = read_stat(pid) {
            children.entry(s.ppid).or_default().push(pid);
            stats.insert(pid, s);
        }
    }
    // Stable order: smallest pid first within each parent.
    for v in children.values_mut() {
        v.sort();
    }

    let mut out: Vec<TreeRow> = Vec::new();

    fn visit(
        pid: i32,
        depth: usize,
        last_at_depth: Vec<bool>,
        is_last_sibling: bool,
        children: &HashMap<i32, Vec<i32>>,
        stats: &HashMap<i32, ProcStat>,
        out: &mut Vec<TreeRow>,
    ) {
        let Some(stat) = stats.get(&pid) else {
            return;
        };
        let uid = proc_uid(pid).unwrap_or(u32::MAX);
        let cmd = read_cmdline(pid);
        let cmdline = if cmd.is_empty() {
            format!("[{}]", stat.comm)
        } else {
            cmd
        };
        out.push(TreeRow {
            pid,
            depth,
            last_at_depth: last_at_depth.clone(),
            is_last_sibling,
            comm: stat.comm.clone(),
            state: stat.state,
            threads: stat.num_threads,
            uid,
            cmdline,
        });

        let kids = children.get(&pid).cloned().unwrap_or_default();
        let n = kids.len();
        for (i, child_pid) in kids.into_iter().enumerate() {
            let mut next = last_at_depth.clone();
            next.push(is_last_sibling);
            let last = i + 1 == n;
            visit(child_pid, depth + 1, next, last, children, stats, out);
        }
    }

    visit(root_pid, 0, Vec::new(), true, &children, &stats, &mut out);
    out
}

/// Returns every numeric pid present in /proc.
pub fn enumerate_pids() -> Vec<i32> {
    let mut out = Vec::new();
    let Ok(rd) = fs::read_dir("/proc") else {
        return out;
    };
    for entry in rd.flatten() {
        let name = entry.file_name();
        if let Some(s) = name.to_str()
            && let Ok(pid) = s.parse::<i32>() {
                out.push(pid);
            }
    }
    out.sort();
    out
}

/// Parse /etc/passwd into a uid→username map. Returns an empty map if the
/// file isn't readable.
pub fn read_user_map() -> HashMap<u32, String> {
    let mut out = HashMap::new();
    let Ok(raw) = fs::read_to_string("/etc/passwd") else {
        return out;
    };
    for line in raw.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 3
            && let Ok(uid) = parts[2].parse::<u32>() {
                out.insert(uid, parts[0].to_string());
            }
    }
    out
}

/// uid owner of /proc/<pid>.
pub fn proc_uid(pid: i32) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    Path::new(&format!("/proc/{pid}"))
        .metadata()
        .ok()
        .map(|m| m.uid())
}

/// Read /proc/<pid>/cmdline (NUL-joined → space-joined), falling back to
/// `[comm]` style if cmdline is empty (kernel threads).
pub fn read_cmdline(pid: i32) -> String {
    if let Ok(raw) = fs::read(format!("/proc/{pid}/cmdline"))
        && !raw.is_empty() {
            return raw
                .split(|&b| b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).to_string())
                .collect::<Vec<_>>()
                .join(" ");
        }
    String::new()
}

pub fn read_threads(pid: i32) -> Result<Vec<ThreadEntry>> {
    let dir = format!("/proc/{pid}/task");
    let mut out = Vec::new();
    for entry in fs::read_dir(&dir).with_context(|| format!("reading {dir}"))? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(tid_str) = name.to_str() else {
            continue;
        };
        let Ok(tid) = tid_str.parse::<i32>() else {
            continue;
        };
        // Read status for name/state
        let status_path = format!("/proc/{pid}/task/{tid}/status");
        let mut tname = String::new();
        let mut tstate = String::new();
        if let Ok(s) = fs::read_to_string(&status_path) {
            for l in s.lines() {
                if let Some(rest) = l.strip_prefix("Name:") {
                    tname = rest.trim().to_string();
                }
                if let Some(rest) = l.strip_prefix("State:") {
                    tstate = rest.trim().to_string();
                }
            }
        }
        let stat_path = format!("/proc/{pid}/task/{tid}/stat");
        let cpu = match fs::read_to_string(&stat_path) {
            Ok(raw) => {
                let close = raw.rfind(')').unwrap_or(0);
                let after = raw[close + 1..].trim();
                let f: Vec<&str> = after.split_whitespace().collect();
                let g = |i: usize| f.get(i).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
                g(11) + g(12)
            }
            Err(_) => 0,
        };
        out.push(ThreadEntry {
            tid,
            name: tname,
            state: tstate,
            cpu_ticks: cpu,
        });
    }
    out.sort_by_key(|t| t.tid);
    Ok(out)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_maps_line() {
        let s = "5db1816f1000-5db1816f3000 r-xp 00002000 08:30 1716                       /usr/bin/head";
        let m = parse_maps_line(s).unwrap();
        assert_eq!(m.start, 0x5db1816f1000);
        assert_eq!(m.end, 0x5db1816f3000);
        assert!(m.perms.r && m.perms.x && !m.perms.shared);
        assert_eq!(m.offset, 0x2000);
        assert_eq!(m.dev, "08:30");
        assert_eq!(m.inode, 1716);
        assert_eq!(m.path, "/usr/bin/head");
    }

    #[test]
    fn parse_anon_line() {
        let s = "7d5676405000-7d5676412000 rw-p 00000000 00:00 0 ";
        let m = parse_maps_line(s).unwrap();
        assert_eq!(m.path, "");
        assert!(m.perms.r && m.perms.w && !m.perms.x);
    }

    #[test]
    fn parse_heap_line() {
        let s = "5db194c57000-5db194c78000 rw-p 00000000 00:00 0                          [heap]";
        let m = parse_maps_line(s).unwrap();
        assert_eq!(m.path, "[heap]");
    }
}
