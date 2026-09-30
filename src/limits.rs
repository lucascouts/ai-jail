//! Whole-sandbox resource limits (`--memory`, `--max-tasks`,
//! `--cpu-quota`, `--cpus`) and the exit report that explains a death.
//!
//! rlimits (`sandbox/rlimits.rs`) are per process: NPROC counts every
//! process the user owns system-wide, and there is no usable memory
//! rlimit (RLIMIT_AS kills JVMs and Chromium for reserving address
//! space). A cgroup caps the sandbox as one unit and counts what it
//! did, which is also what lets the exit report say *why* a child died.
//!
//! No privilege is needed. On a systemd host the user manager already
//! delegates the `memory`, `pids` and `cpu` controllers to the user, and
//! `systemd-run --user --scope` asks it for a fresh scope: ai-jail
//! re-execs itself through it, so the supervisor, the proxy threads and
//! the sandbox share one cgroup. The supervisor staying inside is the
//! point -- it outlives an OOM-killed child and can still read the
//! cgroup's counters before the scope is collected.
//!
//! `cpuset` is *not* delegated by default and enabling it needs root,
//! so `--cpus` uses CPU affinity instead, applied by the in-sandbox
//! wrapper right before seccomp, which then refuses
//! `sched_setaffinity` so nothing inside can widen the set again.

use std::collections::BTreeSet;

/// Upper bound for `--cpus` entries; matches glibc's CPU_SETSIZE.
const MAX_CPU: usize = 1024;

/// Environment marker naming the scope unit ai-jail asked systemd for.
/// Present only between the re-exec and the check in [`enter_scope`].
#[cfg(target_os = "linux")]
const SCOPE_ENV: &str = "AI_JAIL_LIMITS_SCOPE";

/// Resolved, validated limits for one launch.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResourceLimits {
    /// `MemoryMax`, bytes. Swap is pinned to zero alongside it.
    pub memory: Option<u64>,
    /// `TasksMax`: processes *and* threads in the whole sandbox.
    pub max_tasks: Option<u64>,
    /// `CPUQuota`, percent of one CPU (400 = four full CPUs).
    pub cpu_quota: Option<u32>,
    /// CPU affinity for everything inside the sandbox.
    pub cpus: Option<BTreeSet<usize>>,
}

impl ResourceLimits {
    pub fn from_config(config: &crate::config::Config) -> Result<Self, String> {
        Ok(ResourceLimits {
            memory: config
                .memory_max
                .as_deref()
                .map(parse_size)
                .transpose()
                .map_err(|e| format!("memory limit: {e}"))?,
            max_tasks: match config.max_tasks {
                Some(0) => return Err("max-tasks must be at least 1".into()),
                other => other,
            },
            cpu_quota: match config.cpu_quota {
                Some(0) => return Err("cpu-quota must be at least 1%".into()),
                other => other,
            },
            cpus: config
                .cpus
                .as_deref()
                .map(parse_cpu_list)
                .transpose()
                .map_err(|e| format!("cpus: {e}"))?,
        })
    }

    /// Limits that only a cgroup can enforce.
    pub fn needs_scope(&self) -> bool {
        self.memory.is_some()
            || self.max_tasks.is_some()
            || self.cpu_quota.is_some()
    }

    pub fn is_empty(&self) -> bool {
        !self.needs_scope() && self.cpus.is_none()
    }

    /// The `-p KEY=VALUE` properties handed to `systemd-run`. Built only
    /// from validated numbers, never from user text.
    pub fn scope_properties(&self) -> Vec<String> {
        let mut props = Vec::new();
        if let Some(bytes) = self.memory {
            props.push(format!("MemoryMax={bytes}"));
            // Without this the kernel swaps before it kills, and a
            // runaway agent stalls the whole host instead of dying.
            props.push("MemorySwapMax=0".into());
        }
        if let Some(n) = self.max_tasks {
            props.push(format!("TasksMax={n}"));
        }
        if let Some(pct) = self.cpu_quota {
            props.push(format!("CPUQuota={pct}%"));
        }
        props
    }

    /// One line for `--dry-run`, `status` and `--verbose`.
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if let Some(bytes) = self.memory {
            parts.push(format!("memory {}", format_bytes(bytes)));
        }
        if let Some(n) = self.max_tasks {
            parts.push(format!("max-tasks {n}"));
        }
        if let Some(pct) = self.cpu_quota {
            parts.push(format!("cpu-quota {pct}%"));
        }
        if let Some(cpus) = &self.cpus {
            parts.push(format!("cpus {}", format_cpu_list(cpus)));
        }
        parts.join(", ")
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "memory": self.memory,
            "max_tasks": self.max_tasks,
            "cpu_quota": self.cpu_quota,
            "cpus": self.cpus.as_ref().map(format_cpu_list),
        })
    }
}

// ── Parsing ────────────────────────────────────────────────────

/// `512M`, `8G`, `1.5G`, `1073741824`. Suffixes are binary (K = 1024),
/// as systemd reads them. Anything under 1 MiB is refused: it cannot
/// even start the supervisor, and is almost certainly a missing suffix.
pub fn parse_size(text: &str) -> Result<u64, String> {
    let t = text.trim();
    let (number, shift) = match t.char_indices().last() {
        Some((i, c)) if c.is_ascii_alphabetic() => {
            let shift = match c.to_ascii_uppercase() {
                'K' => 10,
                'M' => 20,
                'G' => 30,
                'T' => 40,
                _ => return Err(format!("invalid size suffix in {text:?}")),
            };
            (&t[..i], shift)
        }
        _ => (t, 0),
    };
    let bytes = if let Some((whole, frac)) = number.split_once('.') {
        if shift == 0 || whole.is_empty() || frac.is_empty() {
            return Err(format!("invalid size {text:?}"));
        }
        let whole: u64 = whole
            .parse()
            .map_err(|_| format!("invalid size {text:?}"))?;
        let frac_digits = frac.len().min(6) as u32;
        let frac: u64 = frac[..frac_digits as usize]
            .parse()
            .map_err(|_| format!("invalid size {text:?}"))?;
        let unit = 1u64 << shift;
        whole
            .checked_mul(unit)
            .and_then(|w| w.checked_add(frac * unit / 10u64.pow(frac_digits)))
            .ok_or_else(|| format!("size {text:?} is too large"))?
    } else {
        let n: u64 = number
            .parse()
            .map_err(|_| format!("invalid size {text:?}"))?;
        n.checked_shl(shift)
            .filter(|v| v >> shift == n)
            .ok_or_else(|| format!("size {text:?} is too large"))?
    };
    if bytes < 1 << 20 {
        return Err(format!("size {text:?} is below the 1M minimum"));
    }
    Ok(bytes)
}

/// `400%` or `400`: percent of one CPU.
pub fn parse_percent(text: &str) -> Result<u32, String> {
    let t = text.trim();
    let n: u32 = t
        .strip_suffix('%')
        .unwrap_or(t)
        .parse()
        .map_err(|_| format!("invalid percentage {text:?}"))?;
    if n == 0 {
        return Err("cpu-quota must be at least 1%".into());
    }
    Ok(n)
}

/// `8,24`, `0-3`, `0-3,8`: the `taskset -c` / cpuset list syntax.
pub fn parse_cpu_list(text: &str) -> Result<BTreeSet<usize>, String> {
    let mut set = BTreeSet::new();
    for part in text.split(',') {
        let part = part.trim();
        let cpu = |s: &str| -> Result<usize, String> {
            let n: usize = s
                .trim()
                .parse()
                .map_err(|_| format!("invalid CPU list {text:?}"))?;
            if n >= MAX_CPU {
                return Err(format!("CPU {n} is out of range"));
            }
            Ok(n)
        };
        match part.split_once('-') {
            Some((lo, hi)) => {
                let (lo, hi) = (cpu(lo)?, cpu(hi)?);
                if lo > hi {
                    return Err(format!("invalid CPU range {part:?}"));
                }
                set.extend(lo..=hi);
            }
            None => {
                set.insert(cpu(part)?);
            }
        }
    }
    if set.is_empty() {
        return Err("empty CPU list".into());
    }
    Ok(set)
}

pub fn format_cpu_list(cpus: &BTreeSet<usize>) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut iter = cpus.iter().copied().peekable();
    while let Some(start) = iter.next() {
        let mut end = start;
        while iter.peek() == Some(&(end + 1)) {
            end += 1;
            iter.next();
        }
        out.push(if start == end {
            start.to_string()
        } else {
            format!("{start}-{end}")
        });
    }
    out.join(",")
}

pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

// ── Project-layer tightening ───────────────────────────────────
//
// An untrusted project `.ai-jail` may only tighten. Each helper returns
// the value to keep and whether the project value was (partly) dropped.
// A value that does not parse is kept as-is so the launch fails closed
// at `ResourceLimits::from_config` instead of silently dropping policy.

pub fn tighten_size(
    base: Option<String>,
    local: Option<String>,
) -> (Option<String>, bool) {
    match (base, local) {
        (base, None) => (base, false),
        (None, local) => (local, false),
        (Some(b), Some(l)) => match (parse_size(&b), parse_size(&l)) {
            (Ok(bv), Ok(lv)) if lv <= bv => (Some(l), false),
            (Ok(_), Ok(_)) => (Some(b), true),
            _ => (Some(l), false),
        },
    }
}

pub fn tighten_number<T: Ord>(
    base: Option<T>,
    local: Option<T>,
) -> (Option<T>, bool) {
    match (base, local) {
        (base, None) => (base, false),
        (None, local) => (local, false),
        (Some(b), Some(l)) if l <= b => (Some(l), false),
        (Some(b), Some(_)) => (Some(b), true),
    }
}

/// Project CPUs narrow the baseline to their intersection. CPUs the
/// baseline never allowed are dropped; an empty intersection keeps the
/// baseline whole.
pub fn tighten_cpus(
    base: Option<String>,
    local: Option<String>,
) -> (Option<String>, bool) {
    match (base, local) {
        (base, None) => (base, false),
        (None, local) => (local, false),
        (Some(b), Some(l)) => match (parse_cpu_list(&b), parse_cpu_list(&l)) {
            (Ok(bs), Ok(ls)) => {
                let both: BTreeSet<usize> =
                    bs.intersection(&ls).copied().collect();
                if both.is_empty() {
                    (Some(b), true)
                } else {
                    (Some(format_cpu_list(&both)), both != ls)
                }
            }
            _ => (Some(l), false),
        },
    }
}

// ── CPU affinity ───────────────────────────────────────────────

/// CPUs the calling process may run on right now.
#[cfg(target_os = "linux")]
fn allowed_cpus() -> Result<BTreeSet<usize>, String> {
    use nix::sched::{CpuSet, sched_getaffinity};
    use nix::unistd::Pid;
    let set = sched_getaffinity(Pid::from_raw(0))
        .map_err(|e| format!("cannot read CPU affinity: {e}"))?;
    Ok((0..CpuSet::count())
        .filter(|&i| set.is_set(i).unwrap_or(false))
        .collect())
}

/// Refuse CPUs this process cannot use: the kernel would silently drop
/// them, and `--cpus 40` on a 32-CPU host must not mean "any CPU".
#[cfg(target_os = "linux")]
pub fn validate_cpus(cpus: &BTreeSet<usize>) -> Result<(), String> {
    let allowed = allowed_cpus()?;
    let missing: BTreeSet<usize> = cpus.difference(&allowed).copied().collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "--cpus {} names CPUs this process cannot use: {} (available: {})",
            format_cpu_list(cpus),
            format_cpu_list(&missing),
            format_cpu_list(&allowed)
        ))
    }
}

/// Pin the calling thread -- and everything it later execs or forks --
/// to `cpus`. Must run before seccomp refuses `sched_setaffinity`.
#[cfg(target_os = "linux")]
pub fn apply_cpus(cpus: &BTreeSet<usize>) -> Result<(), String> {
    use nix::sched::{CpuSet, sched_setaffinity};
    use nix::unistd::Pid;
    validate_cpus(cpus)?;
    let mut set = CpuSet::new();
    for &cpu in cpus {
        set.set(cpu)
            .map_err(|e| format!("cannot select CPU {cpu}: {e}"))?;
    }
    sched_setaffinity(Pid::from_raw(0), &set)
        .map_err(|e| format!("cannot set CPU affinity: {e}"))
}

/// OOM score bias for everything inside a memory-limited sandbox.
/// The supervisor shares the cgroup and is what reports the kill, so
/// the kernel must pick the agent first. Raising the bias needs no
/// privilege; it is inherited across fork and exec.
#[cfg(target_os = "linux")]
const SANDBOX_OOM_SCORE_ADJ: &str = "500";

/// Called by the in-sandbox wrapper before it execs the command. Best
/// effort: a failure only makes the report less likely to survive, so
/// it warns instead of refusing the launch.
#[cfg(target_os = "linux")]
pub fn prefer_sandbox_as_oom_victim() {
    if let Err(e) =
        std::fs::write("/proc/self/oom_score_adj", SANDBOX_OOM_SCORE_ADJ)
    {
        crate::output::warn(&format!(
            "cannot raise the sandbox OOM score ({e}); an OOM kill may hit \
             the supervisor and lose the exit report"
        ));
    }
}

// ── Scope entry ────────────────────────────────────────────────

/// The `systemd-run` argument vector that re-execs `exe args…` inside a
/// fresh user scope named `unit`. No shell is involved at any point:
/// the vector goes straight to execvp.
#[cfg(target_os = "linux")]
fn scope_command(
    limits: &ResourceLimits,
    unit: &str,
    exe: &std::path::Path,
    args: &[std::ffi::OsString],
) -> Vec<std::ffi::OsString> {
    let mut argv: Vec<std::ffi::OsString> = vec![
        "systemd-run".into(),
        "--user".into(),
        "--scope".into(),
        "--quiet".into(),
        // systemd-run expands $VAR in the command line by default,
        // which would rewrite any `$` in ai-jail's own arguments.
        "--expand-environment=no".into(),
        format!("--unit={unit}").into(),
    ];
    for prop in limits.scope_properties() {
        argv.push("-p".into());
        argv.push(prop.into());
    }
    argv.push("--".into());
    argv.push(exe.as_os_str().to_owned());
    argv.extend(args.iter().cloned());
    argv
}

/// The cgroup v2 directory of the calling process.
#[cfg(target_os = "linux")]
pub fn own_cgroup_dir() -> Option<std::path::PathBuf> {
    let text = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let path = text.lines().find_map(|l| l.strip_prefix("0::"))?;
    Some(
        std::path::Path::new("/sys/fs/cgroup")
            .join(path.trim_start_matches('/')),
    )
}

fn read_limit(dir: &std::path::Path, file: &str) -> Option<String> {
    std::fs::read_to_string(dir.join(file))
        .ok()
        .map(|s| s.trim().to_string())
}

/// Whether the cgroup at `dir` enforces `limits`. memory.max is kept in
/// pages, so a byte count that is not page-aligned reads back rounded
/// down; anything within one 64 KiB page of the request counts.
fn cgroup_enforces(dir: &std::path::Path, limits: &ResourceLimits) -> bool {
    if let Some(want) = limits.memory {
        let Some(got) =
            read_limit(dir, "memory.max").and_then(|v| v.parse::<u64>().ok())
        else {
            return false;
        };
        if got > want || want - got >= 64 * 1024 {
            return false;
        }
        if read_limit(dir, "memory.swap.max").as_deref() != Some("0") {
            return false;
        }
    }
    if let Some(want) = limits.max_tasks
        && read_limit(dir, "pids.max") != Some(want.to_string())
    {
        return false;
    }
    if let Some(want) = limits.cpu_quota {
        let Some(max) = read_limit(dir, "cpu.max") else {
            return false;
        };
        let mut it = max.split_whitespace();
        let (Some(Ok(quota)), Some(Ok(period))) = (
            it.next().map(str::parse::<u64>),
            it.next().map(str::parse::<u64>),
        ) else {
            return false;
        };
        // systemd rounds the quota to its own granularity; accept 1%.
        let got = quota * 100 / period.max(1);
        if got.abs_diff(u64::from(want)) > 1 {
            return false;
        }
    }
    true
}

/// Make sure this process runs inside a cgroup enforcing `limits`.
///
/// First call: re-exec through `systemd-run --user --scope`, which only
/// returns here on failure. Second call (inside the scope): prove the
/// scope is the one requested *and* that the kernel enforces the
/// limits, or refuse to launch -- a limit the user asked for and did
/// not get must never be silent.
#[cfg(target_os = "linux")]
pub fn enter_scope(
    limits: &ResourceLimits,
    verbose: bool,
) -> Result<(), String> {
    use std::os::unix::process::CommandExt;

    if let Some(unit) = std::env::var_os(SCOPE_ENV) {
        // SAFETY: called from run() before any thread is spawned.
        unsafe { std::env::remove_var(SCOPE_ENV) };
        let unit = unit.to_string_lossy().into_owned();
        let dir = own_cgroup_dir()
            .ok_or("resource limits: cannot read /proc/self/cgroup")?;
        let in_unit = dir.file_name().is_some_and(|name| {
            name.to_string_lossy() == format!("{unit}.scope")
        });
        if !in_unit {
            return Err(format!(
                "resource limits: expected to run in {unit}.scope, found {}",
                dir.display()
            ));
        }
        if !cgroup_enforces(&dir, limits) {
            return Err(format!(
                "resource limits: {} does not enforce {} -- is the \
                 controller delegated to the user manager?",
                dir.display(),
                limits.describe()
            ));
        }
        if verbose {
            crate::output::verbose(&format!(
                "Resource limits: {} ({})",
                limits.describe(),
                dir.display()
            ));
        }
        return Ok(());
    }

    if std::env::var_os("XDG_RUNTIME_DIR").is_none() {
        return Err(
            "resource limits need a systemd user session (XDG_RUNTIME_DIR \
             is unset); --memory, --max-tasks and --cpu-quota are \
             unavailable here"
                .into(),
        );
    }
    let exe = std::env::current_exe()
        .map_err(|e| format!("resource limits: cannot resolve ai-jail: {e}"))?;
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let unit = format!("ai-jail-{}", std::process::id());
    let argv = scope_command(limits, &unit, &exe, &args);
    let mut cmd = std::process::Command::new(&argv[0]);
    cmd.args(&argv[1..]).env(SCOPE_ENV, &unit);
    // Replaces this process: same PID, stdio and signal disposition, so
    // an ACP client talking over stdin/stdout never sees the hop.
    let err = CommandExt::exec(&mut cmd);
    Err(format!(
        "resource limits need systemd-run (systemd user session): {err}"
    ))
}

// ── Accounting and the exit report ─────────────────────────────

/// What the cgroup counted over the launch. Every field is optional
/// because the kernel omits files for controllers that are not enabled.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CgroupReport {
    pub memory_peak: Option<u64>,
    /// Processes the kernel OOM-killed inside the cgroup.
    pub oom_kills: u64,
    /// Times the memory limit was hit (reclaim was forced).
    pub memory_max_hits: u64,
    /// fork/clone attempts refused by the task limit.
    pub tasks_refused: u64,
    pub cpu_usage_usec: Option<u64>,
    pub cpu_throttled_usec: Option<u64>,
}

fn keyed(text: &str, key: &str) -> Option<u64> {
    text.lines().find_map(|line| {
        let (k, v) = line.split_once(' ')?;
        (k == key).then(|| v.trim().parse().ok()).flatten()
    })
}

impl CgroupReport {
    pub fn read(dir: &std::path::Path) -> Self {
        let events = read_limit(dir, "memory.events").unwrap_or_default();
        let pids = read_limit(dir, "pids.events").unwrap_or_default();
        let cpu = read_limit(dir, "cpu.stat").unwrap_or_default();
        CgroupReport {
            memory_peak: read_limit(dir, "memory.peak")
                .and_then(|v| v.parse().ok()),
            oom_kills: keyed(&events, "oom_kill").unwrap_or(0),
            memory_max_hits: keyed(&events, "max").unwrap_or(0),
            tasks_refused: keyed(&pids, "max").unwrap_or(0),
            cpu_usage_usec: keyed(&cpu, "usage_usec"),
            cpu_throttled_usec: keyed(&cpu, "throttled_usec"),
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "memory_peak": self.memory_peak,
            "oom_kills": self.oom_kills,
            "memory_max_hits": self.memory_max_hits,
            "tasks_refused": self.tasks_refused,
            "cpu_usage_usec": self.cpu_usage_usec,
            "cpu_throttled_usec": self.cpu_throttled_usec,
        })
    }
}

/// Signals a user or a harness sends on purpose; their deaths need no
/// explanation.
fn deliberate_signal(sig: i32) -> bool {
    matches!(sig, 1 | 2 | 13 | 15)
}

fn signal_name(sig: i32) -> String {
    nix::sys::signal::Signal::try_from(sig)
        .map(|s| s.as_str().to_string())
        .unwrap_or_else(|_| format!("signal {sig}"))
}

/// Explain an exit that the exit code alone does not. `None` when there
/// is nothing to say (clean exit, or a deliberate signal with no limit
/// involved).
pub fn describe_exit(
    exit_code: i32,
    limits: &ResourceLimits,
    report: Option<&CgroupReport>,
) -> Option<String> {
    let signal = (129..=192).contains(&exit_code).then(|| exit_code - 128);
    let mut lines = Vec::new();

    if let Some(r) = report {
        if r.oom_kills > 0 {
            let limit = limits
                .memory
                .map(format_bytes)
                .unwrap_or_else(|| "unset".into());
            let peak = r
                .memory_peak
                .map(format_bytes)
                .unwrap_or_else(|| "unknown".into());
            lines.push(format!(
                "out of memory: the kernel killed {} process(es) at the \
                 sandbox memory limit ({limit}, peak {peak})",
                r.oom_kills
            ));
        }
        if r.tasks_refused > 0 {
            lines.push(format!(
                "task limit reached: {} fork/clone attempt(s) refused \
                 (max-tasks {})",
                r.tasks_refused,
                limits.max_tasks.map_or("unset".into(), |n| n.to_string())
            ));
        }
    }

    match signal {
        Some(sig) if !lines.is_empty() || deliberate_signal(sig) => {}
        Some(24) => lines
            .push("killed by SIGXCPU: the CPU-time rlimit was reached".into()),
        Some(25) => lines.push(
            "killed by SIGXFSZ: the file-size rlimit was reached \
             (1 GiB under --lockdown)"
                .into(),
        ),
        Some(9) if limits.memory.is_some() => lines.push(
            "killed by SIGKILL, not by the sandbox memory limit (no OOM \
             kill was counted in the sandbox cgroup)"
                .into(),
        ),
        Some(9) => lines.push(
            "killed by SIGKILL; ai-jail set no memory limit, so the usual \
             cause is the host OOM killer (`journalctl -k | grep -i oom`) \
             -- --memory caps the sandbox and makes this report exact"
                .into(),
        ),
        Some(sig) => lines.push(format!("killed by {}", signal_name(sig))),
        None => {}
    }

    if lines.is_empty() {
        None
    } else {
        Some(format!(
            "sandbox exited with {exit_code}: {}",
            lines.join("; ")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cpus(list: &[usize]) -> BTreeSet<usize> {
        list.iter().copied().collect()
    }

    #[test]
    fn size_parses_binary_suffixes() {
        assert_eq!(parse_size("1M").unwrap(), 1 << 20);
        assert_eq!(parse_size("8G").unwrap(), 8 << 30);
        assert_eq!(parse_size("8g").unwrap(), 8 << 30);
        assert_eq!(parse_size("1T").unwrap(), 1 << 40);
        assert_eq!(parse_size("1.5G").unwrap(), 3 << 29);
        assert_eq!(parse_size(" 2048K ").unwrap(), 2 << 20);
        assert_eq!(parse_size("1073741824").unwrap(), 1 << 30);
    }

    #[test]
    fn size_refuses_garbage_tiny_and_overflow() {
        for bad in ["", "G", "8X", "-1G", "1.G", ".5G", "1.5", "8 G", "abc"] {
            assert!(parse_size(bad).is_err(), "{bad:?} should fail");
        }
        assert!(parse_size("512K").is_err(), "below 1M");
        assert!(parse_size("100").is_err(), "bytes without suffix, tiny");
        assert!(parse_size("99999999999T").is_err(), "overflow");
    }

    #[test]
    fn percent_accepts_suffix_or_bare() {
        assert_eq!(parse_percent("400%").unwrap(), 400);
        assert_eq!(parse_percent("50").unwrap(), 50);
        assert!(parse_percent("0%").is_err());
        assert!(parse_percent("-5%").is_err());
        assert!(parse_percent("lots").is_err());
    }

    #[test]
    fn cpu_list_parses_ranges_and_singles() {
        assert_eq!(parse_cpu_list("8,24").unwrap(), cpus(&[8, 24]));
        assert_eq!(parse_cpu_list("0-3").unwrap(), cpus(&[0, 1, 2, 3]));
        assert_eq!(parse_cpu_list("0-1, 4").unwrap(), cpus(&[0, 1, 4]));
        assert_eq!(parse_cpu_list("3,3").unwrap(), cpus(&[3]));
    }

    #[test]
    fn cpu_list_refuses_bad_input() {
        for bad in ["", ",", "a", "3-1", "1-", "-1", "1024", "0-1024"] {
            assert!(parse_cpu_list(bad).is_err(), "{bad:?} should fail");
        }
    }

    #[test]
    fn cpu_list_round_trips_compactly() {
        assert_eq!(
            format_cpu_list(&cpus(&[0, 1, 2, 3, 8, 10, 11])),
            "0-3,8,10-11"
        );
        assert_eq!(format_cpu_list(&cpus(&[5])), "5");
    }

    #[test]
    fn scope_properties_pin_swap_with_memory() {
        let limits = ResourceLimits {
            memory: Some(8 << 30),
            max_tasks: Some(2000),
            cpu_quota: Some(400),
            cpus: None,
        };
        assert_eq!(
            limits.scope_properties(),
            vec![
                "MemoryMax=8589934592",
                "MemorySwapMax=0",
                "TasksMax=2000",
                "CPUQuota=400%",
            ]
        );
        assert!(limits.needs_scope());
    }

    #[test]
    fn cpus_alone_need_no_scope() {
        let limits = ResourceLimits {
            cpus: Some(cpus(&[0])),
            ..Default::default()
        };
        assert!(!limits.needs_scope());
        assert!(!limits.is_empty());
        assert!(limits.scope_properties().is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn scope_command_disables_expansion_and_keeps_args_verbatim() {
        let limits = ResourceLimits {
            memory: Some(1 << 30),
            ..Default::default()
        };
        let argv = scope_command(
            &limits,
            "ai-jail-42",
            std::path::Path::new("/usr/bin/ai-jail"),
            &["--env".into(), "X=$HOME".into(), "claude".into()],
        );
        let argv: Vec<String> = argv
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(argv[0], "systemd-run");
        assert!(argv.contains(&"--expand-environment=no".to_string()));
        assert!(argv.contains(&"--unit=ai-jail-42".to_string()));
        let sep = argv.iter().position(|a| a == "--").unwrap();
        assert_eq!(
            &argv[sep + 1..],
            &["/usr/bin/ai-jail", "--env", "X=$HOME", "claude"]
        );
    }

    #[test]
    fn tighten_size_keeps_the_smaller() {
        let s = |v: &str| Some(v.to_string());
        assert_eq!(tighten_size(s("8G"), s("4G")), (s("4G"), false));
        assert_eq!(tighten_size(s("4G"), s("8G")), (s("4G"), true));
        assert_eq!(tighten_size(None, s("4G")), (s("4G"), false));
        assert_eq!(tighten_size(s("4G"), None), (s("4G"), false));
        // Unparsable project value is kept, so the launch fails closed.
        assert_eq!(tighten_size(s("4G"), s("lots")), (s("lots"), false));
    }

    #[test]
    fn tighten_number_keeps_the_smaller() {
        assert_eq!(tighten_number(Some(100), Some(50)), (Some(50), false));
        assert_eq!(tighten_number(Some(50), Some(100)), (Some(50), true));
        assert_eq!(tighten_number(None, Some(7)), (Some(7), false));
        assert_eq!(tighten_number::<u32>(None, None), (None, false));
    }

    #[test]
    fn tighten_cpus_intersects() {
        let s = |v: &str| Some(v.to_string());
        assert_eq!(tighten_cpus(s("0-7"), s("2-3")), (s("2-3"), false));
        // CPUs outside the baseline are dropped, with a warning.
        assert_eq!(tighten_cpus(s("0-3"), s("2-5")), (s("2-3"), true));
        // Disjoint: the project cannot move the sandbox elsewhere.
        assert_eq!(tighten_cpus(s("0-3"), s("8-9")), (s("0-3"), true));
        assert_eq!(tighten_cpus(None, s("1")), (s("1"), false));
    }

    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir()
            .join(format!("ai-jail-{tag}-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn cgroup_enforcement_is_read_back_from_files() {
        let dir = scratch("limits");
        let write = |f: &str, v: &str| std::fs::write(dir.join(f), v).unwrap();
        write("memory.max", "8589934592\n");
        write("memory.swap.max", "0\n");
        write("pids.max", "2000\n");
        write("cpu.max", "400000 100000\n");
        let limits = ResourceLimits {
            memory: Some(8 << 30),
            max_tasks: Some(2000),
            cpu_quota: Some(400),
            cpus: None,
        };
        assert!(cgroup_enforces(&dir, &limits));

        write("memory.swap.max", "max\n");
        assert!(!cgroup_enforces(&dir, &limits), "swap must be pinned");
        write("memory.swap.max", "0\n");
        write("pids.max", "max\n");
        assert!(!cgroup_enforces(&dir, &limits), "pids.max unset");
        write("pids.max", "2000\n");
        write("cpu.max", "max 100000\n");
        assert!(!cgroup_enforces(&dir, &limits), "cpu.max unset");
        write("cpu.max", "400000 100000\n");
        write("memory.max", "max\n");
        assert!(!cgroup_enforces(&dir, &limits), "memory.max unset");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn cgroup_report_reads_kernel_counters() {
        let dir = scratch("report");
        std::fs::write(
            dir.join("memory.events"),
            "low 0\nhigh 0\nmax 40\noom 1\noom_kill 1\noom_group_kill 0\n",
        )
        .unwrap();
        std::fs::write(dir.join("memory.peak"), "67108864\n").unwrap();
        std::fs::write(dir.join("pids.events"), "max 3\n").unwrap();
        std::fs::write(
            dir.join("cpu.stat"),
            "usage_usec 23737\nuser_usec 1\nsystem_usec 2\nnr_periods 0\n\
             nr_throttled 0\nthrottled_usec 0\n",
        )
        .unwrap();
        let report = CgroupReport::read(&dir);
        assert_eq!(
            report,
            CgroupReport {
                memory_peak: Some(64 << 20),
                oom_kills: 1,
                memory_max_hits: 40,
                tasks_refused: 3,
                cpu_usage_usec: Some(23737),
                cpu_throttled_usec: Some(0),
            }
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn cgroup_report_tolerates_missing_files() {
        let report =
            CgroupReport::read(std::path::Path::new("/nonexistent/ai-jail"));
        assert_eq!(report, CgroupReport::default());
    }

    #[test]
    fn exit_report_names_the_oom_kill() {
        let limits = ResourceLimits {
            memory: Some(64 << 20),
            ..Default::default()
        };
        let report = CgroupReport {
            memory_peak: Some(64 << 20),
            oom_kills: 1,
            ..Default::default()
        };
        let msg = describe_exit(137, &limits, Some(&report)).unwrap();
        assert!(msg.contains("out of memory"), "{msg}");
        assert!(msg.contains("64.0 MiB"), "{msg}");
        assert!(!msg.contains("SIGKILL"), "{msg}");
    }

    #[test]
    fn exit_report_names_refused_forks() {
        let limits = ResourceLimits {
            max_tasks: Some(20),
            ..Default::default()
        };
        let report = CgroupReport {
            tasks_refused: 5,
            ..Default::default()
        };
        let msg = describe_exit(1, &limits, Some(&report)).unwrap();
        assert!(msg.contains("5 fork/clone"), "{msg}");
        assert!(msg.contains("max-tasks 20"), "{msg}");
    }

    #[test]
    fn exit_report_explains_an_unlimited_sigkill() {
        let msg = describe_exit(137, &ResourceLimits::default(), None).unwrap();
        assert!(msg.contains("host OOM killer"), "{msg}");
    }

    #[test]
    fn exit_report_names_rlimit_signals() {
        let none = ResourceLimits::default();
        assert!(describe_exit(152, &none, None).unwrap().contains("SIGXCPU"));
        assert!(describe_exit(153, &none, None).unwrap().contains("SIGXFSZ"));
        assert!(describe_exit(139, &none, None).unwrap().contains("SIGSEGV"));
    }

    #[test]
    fn exit_report_stays_quiet_for_normal_and_deliberate_exits() {
        let none = ResourceLimits::default();
        assert_eq!(describe_exit(0, &none, None), None);
        assert_eq!(describe_exit(1, &none, None), None);
        assert_eq!(describe_exit(130, &none, None), None, "SIGINT");
        assert_eq!(describe_exit(143, &none, None), None, "SIGTERM");
        assert_eq!(
            describe_exit(0, &none, Some(&CgroupReport::default())),
            None
        );
    }
}
