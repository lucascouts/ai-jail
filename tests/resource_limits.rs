// End-to-end tests for the whole-sandbox resource limits: `--cpus`
// (CPU affinity locked by seccomp) and `--memory` / `--max-tasks` /
// `--cpu-quota` (a systemd user scope), plus the exit report that
// explains a death.
//
// Linux-only. Tests needing bwrap skip when it cannot create user
// namespaces; tests needing a cgroup skip when `systemd-run --user
// --scope` is unavailable (no systemd user session).
#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::OnceLock;

fn bwrap_available() -> bool {
    static RESULT: OnceLock<bool> = OnceLock::new();
    *RESULT.get_or_init(|| {
        Command::new("bwrap")
            .args([
                "--ro-bind",
                "/",
                "/",
                "--proc",
                "/proc",
                "--unshare-pid",
                "--",
                "true",
            ])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    })
}

fn scope_available() -> bool {
    static RESULT: OnceLock<bool> = OnceLock::new();
    *RESULT.get_or_init(|| {
        Command::new("systemd-run")
            .args([
                "--user",
                "--scope",
                "--quiet",
                "-p",
                "TasksMax=100",
                "true",
            ])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    })
}

macro_rules! require {
    ($cond:expr, $why:literal) => {
        if !$cond {
            eprintln!(concat!("SKIPPED: ", $why));
            return;
        }
    };
}

fn ai_jail() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ai-jail"))
}

fn test_tree(name: &str) -> (PathBuf, PathBuf) {
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("resource-limits-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let project = root.join("project");
    let home = root.join("home");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    (project, home)
}

fn run_in(name: &str, args: &[&str]) -> (Output, PathBuf) {
    let (project, home) = test_tree(name);
    let output = Command::new(ai_jail())
        .args(["--clean", "--no-save-config", "--no-status-bar"])
        .args(args)
        .current_dir(&project)
        .env("HOME", &home)
        .env_remove("AI_JAIL_LIMITS_SCOPE")
        .output()
        .expect("failed to run ai-jail");
    (output, home)
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// The first CPU this test process may run on (not necessarily 0).
fn first_allowed_cpu() -> usize {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let list = status
        .lines()
        .find_map(|l| l.strip_prefix("Cpus_allowed_list:"))
        .unwrap()
        .trim();
    list.split([',', '-']).next().unwrap().parse().unwrap()
}

fn launch_record(home: &std::path::Path) -> serde_json::Value {
    let log = home.join(".local/share/ai-jail/history.jsonl");
    let content = std::fs::read_to_string(&log).expect("audit log written");
    content
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .find(|v| v["type"] == "launch")
        .expect("launch record")
}

// ── --cpus ─────────────────────────────────────────────────────

#[test]
fn cpus_pin_the_sandbox_and_cannot_be_widened() {
    require!(bwrap_available(), "bwrap cannot create user namespaces");
    let cpu = first_allowed_cpu().to_string();
    let (output, _) = run_in(
        "cpus-pin",
        &[
            "--exec",
            "--cpus",
            &cpu,
            "bash",
            "-c",
            "grep Cpus_allowed_list /proc/self/status; \
             echo nproc=$(nproc); \
             taskset -p -c 0-$(( $(getconf _NPROCESSORS_CONF) - 1 )) $$ \
               >/dev/null 2>&1; echo widen=$?; \
             grep Cpus_allowed_list /proc/self/status",
        ],
    );
    let stdout = text(&output.stdout);
    assert!(output.status.success(), "{stdout} {}", text(&output.stderr));
    let lists: Vec<&str> = stdout
        .lines()
        .filter_map(|l| l.strip_prefix("Cpus_allowed_list:"))
        .map(str::trim)
        .collect();
    assert_eq!(lists, vec![cpu.as_str(), cpu.as_str()], "{stdout}");
    assert!(stdout.contains("nproc=1"), "{stdout}");
    assert!(
        !stdout.contains("widen=0"),
        "taskset widened the CPU set: {stdout}"
    );
}

#[test]
fn cpus_without_seccomp_are_refused() {
    let (output, _) = run_in(
        "cpus-noseccomp",
        &["--exec", "--no-seccomp", "--cpus", "0", "true"],
    );
    assert!(!output.status.success());
    assert!(
        text(&output.stderr).contains("--cpus needs seccomp"),
        "{}",
        text(&output.stderr)
    );
}

#[test]
fn cpus_the_host_does_not_have_are_refused() {
    let (output, _) =
        run_in("cpus-missing", &["--exec", "--cpus", "1023", "true"]);
    assert!(!output.status.success());
    assert!(
        text(&output.stderr).contains("cannot use: 1023"),
        "{}",
        text(&output.stderr)
    );
}

// ── cgroup scope ───────────────────────────────────────────────

#[test]
fn memory_limit_death_is_reported_as_oom() {
    require!(bwrap_available(), "bwrap cannot create user namespaces");
    require!(scope_available(), "no systemd user session");
    let (output, home) = run_in(
        "oom",
        &[
            "--exec",
            "--audit-log",
            "--memory",
            "64M",
            "bash",
            "-c",
            // Command substitution holds the whole output in memory.
            "x=$(head -c 256M /dev/zero | tr '\\0' a); echo ${#x}",
        ],
    );
    let stderr = text(&output.stderr);
    assert_ne!(output.status.code(), Some(0), "{stderr}");
    assert!(stderr.contains("out of memory"), "{stderr}");
    assert!(stderr.contains("64.0 MiB"), "{stderr}");

    let record = launch_record(&home);
    assert_eq!(record["limits"]["memory"], 64 << 20);
    assert!(
        record["cgroup"]["oom_kills"].as_u64().unwrap() >= 1,
        "{record}"
    );
    assert!(record["cgroup"]["memory_peak"].as_u64().is_some());
}

#[test]
fn task_limit_refusals_are_reported() {
    require!(bwrap_available(), "bwrap cannot create user namespaces");
    require!(scope_available(), "no systemd user session");
    let (output, _) = run_in(
        "tasks",
        &[
            "--exec",
            "--max-tasks",
            "40",
            "bash",
            "-c",
            "for i in $(seq 80); do sleep 1 & done 2>/dev/null; wait",
        ],
    );
    let stderr = text(&output.stderr);
    assert!(stderr.contains("task limit reached"), "{stderr}");
    assert!(stderr.contains("max-tasks 40"), "{stderr}");
}

#[test]
fn a_clean_run_under_limits_is_quiet_and_accounted() {
    require!(bwrap_available(), "bwrap cannot create user namespaces");
    require!(scope_available(), "no systemd user session");
    let (output, home) = run_in(
        "clean",
        &[
            "--exec",
            "--audit-log",
            "--memory",
            "512M",
            "--max-tasks",
            "500",
            "--cpu-quota",
            "150%",
            "bash",
            "-c",
            "exit 4",
        ],
    );
    assert_eq!(output.status.code(), Some(4), "{}", text(&output.stderr));
    assert_eq!(text(&output.stderr), "", "no report for a normal exit");
    let record = launch_record(&home);
    assert_eq!(record["exit_code"], 4);
    assert_eq!(record["limits"]["max_tasks"], 500);
    assert_eq!(record["limits"]["cpu_quota"], 150);
    assert_eq!(record["cgroup"]["oom_kills"], 0);
    assert!(record["cgroup"]["cpu_usage_usec"].as_u64().is_some());
}

#[test]
fn the_sandbox_not_the_supervisor_is_the_oom_victim() {
    require!(bwrap_available(), "bwrap cannot create user namespaces");
    require!(scope_available(), "no systemd user session");
    let read = "cat /proc/self/oom_score_adj";
    let (limited, _) = run_in(
        "oomadj",
        &["--exec", "--memory", "256M", "bash", "-c", read],
    );
    assert_eq!(text(&limited.stdout).trim(), "500");
    let (plain, _) = run_in("oomadj-plain", &["--exec", "bash", "-c", read]);
    assert_ne!(
        text(&plain.stdout).trim(),
        "500",
        "no --memory, no bias: behaviour unchanged"
    );
}

#[test]
fn arguments_survive_the_scope_hop_verbatim() {
    require!(bwrap_available(), "bwrap cannot create user namespaces");
    require!(scope_available(), "no systemd user session");
    let (output, _) = run_in(
        "verbatim",
        &[
            "--exec",
            "--memory",
            "256M",
            "bash",
            "-c",
            "printf '%s|%s' \"$1\" \"$2\"",
            "_",
            "lit$HOME",
            "a b;c",
        ],
    );
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert_eq!(text(&output.stdout), "lit$HOME|a b;c");
}

#[test]
fn a_spoofed_scope_marker_is_refused() {
    // The marker only names the scope to check; claiming one that this
    // process is not in must stop the launch, not skip the limits.
    let (project, home) = test_tree("spoof");
    let output = Command::new(ai_jail())
        .args([
            "--clean",
            "--no-save-config",
            "--exec",
            "--memory",
            "256M",
            "true",
        ])
        .current_dir(&project)
        .env("HOME", &home)
        .env("AI_JAIL_LIMITS_SCOPE", "not-this-one")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        text(&output.stderr).contains("expected to run in not-this-one.scope"),
        "{}",
        text(&output.stderr)
    );
}

#[test]
fn dry_run_names_the_scope_without_entering_it() {
    let (output, _) = run_in(
        "dryrun",
        &["--dry-run", "--memory", "1G", "--cpus", "0", "bash"],
    );
    assert!(output.status.success(), "{}", text(&output.stderr));
    let stderr = text(&output.stderr);
    assert!(stderr.contains("-p MemoryMax=1073741824"), "{stderr}");
    assert!(stderr.contains("-p MemorySwapMax=0"), "{stderr}");
    let stdout = text(&output.stdout);
    assert!(stdout.contains("--cpus 0"), "wrapper gets --cpus: {stdout}");
}
