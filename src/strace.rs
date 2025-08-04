use anyhow::{Context, Result};
use std::collections::VecDeque;
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

const MAX_LINES: usize = 5000;

pub struct StraceSession {
    child: Option<Child>,
    lines: Arc<Mutex<VecDeque<String>>>,
    thread: Option<JoinHandle<()>>,
}

impl StraceSession {
    pub fn start(pid: i32) -> Result<Self> {
        let mut cmd = Command::new("strace");
        cmd.args([
            "-p",
            &pid.to_string(),
            "-f",      // follow forks
            "-tt",     // microsecond timestamps
            "-s",      // string length
            "256",
            "-y",      // decode fds to paths
        ]);
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::piped());
        let mut child = cmd
            .spawn()
            .with_context(|| "spawning strace. Is it installed, and is /proc/<pid> attachable?")?;

        let stderr = child
            .stderr
            .take()
            .context("strace process exposed no stderr pipe")?;
        let lines: Arc<Mutex<VecDeque<String>>> = Arc::new(Mutex::new(VecDeque::with_capacity(MAX_LINES)));
        let lines_t = Arc::clone(&lines);
        let thread = std::thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines() {
                let Ok(line) = line else { break };
                let mut buf = lines_t.lock().unwrap();
                if buf.len() == MAX_LINES {
                    buf.pop_front();
                }
                buf.push_back(line);
            }
        });

        Ok(StraceSession {
            child: Some(child),
            lines,
            thread: Some(thread),
        })
    }

    pub fn snapshot(&self) -> Vec<String> {
        self.lines.lock().unwrap().iter().cloned().collect()
    }

    pub fn clear(&self) {
        self.lines.lock().unwrap().clear();
    }
}

impl Drop for StraceSession {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            // SIGKILL the tracer; the kernel auto-detaches strace from the
            // target when the tracer dies, so the traced process resumes.
            let _ = c.kill();
            let _ = c.wait();
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}
