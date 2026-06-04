# scry

![scry inspecting a containerized nginx](vhs/demo.gif)

A terminal UI process inspector for Linux. Point it at a pid and get live, annotated views of a processes: memory map, threads, open files, limits, cgroup membership, environment, capabilities, namespaces, security posture, kernel stack, and a live syscall stream (requires strace).

## Why

There's many tools that offer a lot of what this tool does, but none that I could find that satisfied the Swiss army knife style that I was after (and the set of things that I generally care about). I'm open to any new additions in the list that someone finds useful as well.

The name is in reference to [scrying](https://en.wikipedia.org/wiki/Scrying).

## Features

- **Process picker** — sortable, filterable list of every process you can see, with cpu/rss/pid/name/user sorts. Skip it by passing a pid on the command line.
- **Memory map** — `/proc/<pid>/maps` + `smaps` rolled up per VMA, with size/RSS/PSS columns, category annotations (heap, main stack, thread stack, dynamic loader, shared libs, anon mmaps, vdso/vsyscall/vvar, file-backed regions), and a category-aware filter.
- **Threads** — per-thread tid, name, state, user/system ticks.
- **Child process tree** — recursive descendants. Enter on a child re-attaches.
- **Open file descriptors** — sockets (with IP:port and protocol), pipes, eventfds, signalfds, timerfds, anon inodes, plain files. Decoded from `/proc/<pid>/fd` symlinks plus `/proc/net/{tcp,tcp6,udp,udp6,unix}`.
- **Resource limits** — every `RLIMIT_*` with soft/hard values.
- **Cgroup membership** — v2 unified path, plus live values from the relevant `/sys/fs/cgroup/...` knobs (memory.current, cpu.stat, pids.current, io.stat, ...).
- **Environment** — `/proc/<pid>/environ` parsed into a table. Captured at exec time, not live.
- **Capabilities** — decoded `CAP_*` bits across inheritable/permitted/effective/bounding/ambient sets.
- **Namespaces** — per-namespace inodes (pid, mnt, net, user, ipc, uts, cgroup, time), with the ones that differ from init flagged.
- **Security overview** — seccomp mode, NoNewPrivs, AppArmor / SELinux label, Yama ptrace policy, a one-line sandbox verdict.
- **Kernel stack** — `/proc/<pid>/stack` for the main thread, or `/proc/<pid>/task/*/stack` swept across all threads. Toggle between full stack and just the `wchan` symbol (where the task is parked).
- **Syscall trace** — attaches `strace -p` in the background and streams it live. Pause, clear, scroll.
- **Send signal** — pick any standard signal or any `SIGRTMIN..SIGRTMAX` and deliver it.

Live screens auto-refresh once per second. Press `Z` to freeze, htop-style.

## Build

Requires Rust 1.88+. Linux only.

```sh
cargo build --release
```

## Usage

```sh
scry              # opens the process picker
scry --pid 12345  # attaches directly to pid 12345
scry -p 12345     # short form
SCRY_PID=12345 scry
```

A few things need root (or the relevant capability):

- **Kernel stack** — reading another process's `/proc/<pid>/stack` requires `CAP_SYS_ADMIN`. As your own user you can only see your own processes' stacks (and even those are gated by `kernel.kptr_restrict`).
- **Syscall trace** — `strace -p` needs ptrace permission for the target. With Yama `ptrace_scope=1` (the common default) that means same-uid or root.
- **Open files of other users** — reading symlinks under `/proc/<other-pid>/fd/` needs root.

## Keys

| Key       | Action                                              |
|-----------|-----------------------------------------------------|
| `↑/↓` `j/k` | Move selection / scroll                           |
| `PgUp` / `PgDn` | Page                                          |
| `Home` / `End`  | Top / bottom                                  |
| `Enter`   | Activate (open menu item, attach to pid/child, send signal) |
| `Esc`     | Back to menu (from menu or picker, exits)           |
| `R`       | Manual refresh                                      |
| `Z`       | Freeze / unfreeze auto-refresh                      |
| `?`       | Toggle help overlay (per-screen)                    |
| `q`       | Quit                                                |
| `/`       | Start typing a filter (picker, maps, signals)       |
| `s` / `r` | Cycle sort / reverse (picker, maps)                 |

Per-screen extras:

- **Syscalls**: `Space` pause/resume, `c` clear buffer.
- **Kernel stack**: `w` toggle wchan vs full stack, `t` toggle main thread vs all threads.
- **Menu**: `P` jumps straight back to the process picker.

Mouse works too: scroll wheel moves selection on lists, left click on a row selects it (single-click activates on the menu).

## Limitations

- Linux only. I don't have much interest in making a variant of this for other operating systems, but I'm all ears.
- The syscall screen requires `strace` to be installed and on `$PATH`.
- The environment screen is captured at exec time. If a process re-`execve`s or rewrites its own `/proc/self/environ`, you'll see the new view, but in-memory `setenv` calls do not update it.
