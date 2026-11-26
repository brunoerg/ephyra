//! Crash-isolated child process manager for `cluster_worker_san` / `cluster_worker_cov`.
//!
//! Runs Bitcoin Core's real `CTxMemPool` / `MemPoolAccept` / `BlockAssembler` / `MiniMiner`
//! inside a child process. Any C++ `assert()`, `Assume()`, ASan, UBSan, or timeout turns into
//! a structured Rust `WorkerCrash` that Ephyra can categorize via `ephyra::signature(...)`
//! and shrink cleanly!

use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct WorkerCrash {
    pub signature: String,
    pub detail: String,
}

pub struct MempoolWorker {
    bin: PathBuf,
    timeout: Duration,
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    rx: Option<Receiver<std::io::Result<String>>>,
    stderr_rx: Option<Receiver<String>>,
}

impl MempoolWorker {
    pub fn default_san() -> Self {
        let mode = std::env::var("CLUSTER_WORKER_MODE").unwrap_or_else(|_| "san".to_string());
        let bin = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/workers")
            .join(format!("cluster_worker_{mode}"));
        Self::new(bin, Duration::from_secs(15))
    }

    pub fn new(bin: PathBuf, timeout: Duration) -> Self {
        Self {
            bin,
            timeout,
            child: None,
            stdin: None,
            rx: None,
            stderr_rx: None,
        }
    }

    fn ensure_started(&mut self) {
        if self.child.is_some() {
            return;
        }
        assert!(
            self.bin.exists(),
            "worker binary missing at {} — run scripts/build_workers.sh",
            self.bin.display()
        );
        let mut cmd = Command::new(&self.bin);
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env("ASAN_OPTIONS", "detect_leaks=0:abort_on_error=1:halt_on_error=1")
            .env("UBSAN_OPTIONS", "print_stacktrace=1:halt_on_error=1:abort_on_error=1");
        let mut child = cmd.spawn().expect("spawn cluster_worker");
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let mut stderr = child.stderr.take().unwrap();

        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut r = BufReader::new(stdout);
            loop {
                let mut line = String::new();
                match r.read_line(&mut line) {
                    Ok(0) => {
                        let _ = tx.send(Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "worker EOF",
                        )));
                        break;
                    }
                    Ok(_) => {
                        if tx.send(Ok(line)).is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Err(e));
                        break;
                    }
                }
            }
        });

        let (stx, srx) = mpsc::channel();
        thread::spawn(move || {
            let mut buf = String::new();
            let _ = stderr.read_to_string(&mut buf);
            let _ = stx.send(buf);
        });

        self.child = Some(child);
        self.stdin = Some(stdin);
        self.rx = Some(rx);
        self.stderr_rx = Some(srx);
    }

    pub fn kill(&mut self) {
        self.stdin.take();
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        self.rx.take();
        self.stderr_rx.take();
    }

    fn collect_crash(&mut self, reason: &str) -> WorkerCrash {
        self.stdin.take();
        let status = if let Some(mut c) = self.child.take() {
            // Wait briefly for crash stderr flush; kill if timed out.
            if reason == "timeout" {
                let _ = c.kill();
            }
            c.wait().ok()
        } else {
            None
        };
        let stderr = self
            .stderr_rx
            .take()
            .and_then(|rx| rx.recv_timeout(Duration::from_secs(2)).ok())
            .unwrap_or_default();
        self.rx.take();

        let sig = extract_signature(reason, &stderr);
        let detail = format!("status={status:?}\n{stderr}");
        WorkerCrash {
            signature: sig,
            detail,
        }
    }

    pub fn send(&mut self, line: &str) -> Result<String, WorkerCrash> {
        self.ensure_started();
        if let Some(stdin) = self.stdin.as_mut() {
            if writeln!(stdin, "{line}").is_err() || stdin.flush().is_err() {
                return Err(self.collect_crash("write_failed"));
            }
        }
        let rx = self.rx.as_ref().unwrap();
        match rx.recv_timeout(self.timeout) {
            Ok(Ok(resp)) => Ok(resp.trim_end().to_string()),
            Ok(Err(_)) => Err(self.collect_crash("crash_eof")),
            Err(RecvTimeoutError::Timeout) => Err(self.collect_crash("timeout")),
            Err(RecvTimeoutError::Disconnected) => Err(self.collect_crash("disconnected")),
        }
    }
}

impl Drop for MempoolWorker {
    fn drop(&mut self) {
        if let Some(stdin) = self.stdin.as_mut() {
            let _ = writeln!(stdin, "QUIT");
            let _ = stdin.flush();
        }
        self.stdin.take();
        if let Some(mut c) = self.child.take() {
            let _ = c.wait();
        }
    }
}

fn extract_signature(reason: &str, stderr: &str) -> String {
    for line in stderr.lines() {
        let l = line.trim();
        if l.contains("runtime error:") {
            // UBSan line: file:line:col: runtime error: ...
            return format!("ubsan: {}", l.chars().take(120).collect::<String>());
        }
        if l.contains("ERROR: AddressSanitizer:") {
            return format!("asan: {}", l.chars().take(120).collect::<String>());
        }
        if l.contains("Assertion") && l.contains("failed") {
            return format!("assert: {}", l.chars().take(120).collect::<String>());
        }
        if l.contains("Internal bug detected:") || l.contains("CHECK_PKG_RESULT_FAILED:") {
            return format!("assume: {}", l.chars().take(120).collect::<String>());
        }
    }
    format!("worker_{reason}")
}
