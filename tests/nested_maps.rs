// End-to-end tests for nested maps: a read-only map strictly inside a
// read-write map stays read-only, and the rest of the parent stays
// writable. The typical use is agent state -- `--rw-map ~/.claude` with
// `--map ~/.claude/hooks` and `--map ~/.claude/settings.json`, so the
// jailed agent keeps its history but cannot plant a hook that a later,
// unjailed session would run.
//
// Linux-only (requires bwrap); tests skip gracefully when unavailable.
#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};

static SANDBOX_RUN_LOCK: Mutex<()> = Mutex::new(());

fn bwrap_available() -> bool {
    static RESULT: OnceLock<bool> = OnceLock::new();
    *RESULT.get_or_init(|| {
        Command::new("bwrap")
            .args(["--ro-bind", "/", "/", "--unshare-pid", "--", "true"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    })
}

fn ai_jail() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ai-jail"))
}

/// A fresh state dir shaped like agent state, plus a project dir.
fn fixture(name: &str) -> (PathBuf, PathBuf) {
    let root = std::env::temp_dir()
        .join(format!("ai-jail-nested.{}.{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let state = root.join("state");
    std::fs::create_dir_all(state.join("hooks")).unwrap();
    std::fs::create_dir_all(state.join("projects")).unwrap();
    std::fs::write(state.join("settings.json"), "orig\n").unwrap();
    std::fs::write(state.join("hooks/h.sh"), "echo hook\n").unwrap();
    let project = root.join("project");
    std::fs::create_dir_all(&project).unwrap();
    (root, state)
}

/// Run `bash -c <script>` with `--rw-map <state>` plus RO children,
/// returning one `label: ALLOWED|blocked` line per probe.
fn probe(
    state: &Path,
    ro_children: &[&str],
    probes: &[(&str, &str)],
) -> String {
    let _lock = SANDBOX_RUN_LOCK.lock().unwrap();
    let mut script = String::new();
    for (label, cmd) in probes {
        script.push_str(&format!(
            "if ( {cmd} ) 2>/dev/null; then echo '{label}: ALLOWED'; \
             else echo '{label}: blocked'; fi\n"
        ));
    }
    let mut command = Command::new(ai_jail());
    command
        .args(["--clean", "--no-status-bar", "--exec", "--no-save-config"])
        .arg("--rw-map")
        .arg(state);
    for child in ro_children {
        command.arg("--map").arg(state.join(child));
    }
    let project = state.parent().unwrap().join("project");
    let output = command
        .current_dir(&project)
        .env("S", state)
        .args(["--env", "S", "bash", "-c", &script])
        .output()
        .expect("failed to spawn ai-jail");
    assert!(
        output.status.success(),
        "sandbox run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn ro_children_stay_read_only_inside_rw_parent() {
    if !bwrap_available() {
        eprintln!("SKIPPED: bwrap unavailable");
        return;
    }
    let (root, state) = fixture("children");
    let out = probe(
        &state,
        &["hooks", "settings.json"],
        &[
            ("write parent", "echo x > \"$S/projects/x\""),
            ("edit hook", "echo evil >> \"$S/hooks/h.sh\""),
            ("new hook", "echo evil > \"$S/hooks/evil.sh\""),
            ("edit settings", "echo evil >> \"$S/settings.json\""),
            (
                "replace settings",
                "echo evil > \"$S/t.json\" && mv -f \"$S/t.json\" \"$S/settings.json\"",
            ),
            ("move hooks away", "mv \"$S/hooks\" \"$S/hooks.old\""),
            ("delete settings", "rm -f \"$S/settings.json\""),
        ],
    );
    let host_settings =
        std::fs::read_to_string(state.join("settings.json")).unwrap();
    let host_hook = std::fs::read_to_string(state.join("hooks/h.sh")).unwrap();
    let wrote_parent = state.join("projects/x").exists();
    let _ = std::fs::remove_dir_all(&root);

    assert!(out.contains("write parent: ALLOWED"), "{out}");
    for label in [
        "edit hook",
        "new hook",
        "edit settings",
        "replace settings",
        "move hooks away",
        "delete settings",
    ] {
        assert!(out.contains(&format!("{label}: blocked")), "{out}");
    }
    assert_eq!(host_settings, "orig\n");
    assert_eq!(host_hook, "echo hook\n");
    assert!(wrote_parent);
}

#[test]
fn rw_map_under_ro_map_is_still_refused() {
    // The other direction keeps upstream's policy: an RO map is a
    // boundary, and nothing beneath it may become writable.
    if !bwrap_available() {
        eprintln!("SKIPPED: bwrap unavailable");
        return;
    }
    let (root, state) = fixture("boundary");
    let _lock = SANDBOX_RUN_LOCK.lock().unwrap();
    let output = Command::new(ai_jail())
        .args(["--clean", "--no-status-bar", "--exec", "--no-save-config"])
        .arg("--map")
        .arg(&state)
        .arg("--rw-map")
        .arg(state.join("projects"))
        .current_dir(root.join("project"))
        .args(["bash", "-c"])
        .arg(format!(
            "echo x > '{}' 2>/dev/null && echo ALLOWED || echo blocked",
            state.join("projects/x").display()
        ))
        .output()
        .expect("failed to spawn ai-jail");
    let _ = std::fs::remove_dir_all(&root);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(stdout.trim(), "blocked");
    assert!(stderr.contains("overlaps a read-only map"), "{stderr}");
}
