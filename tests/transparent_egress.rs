// End-to-end tests for `--transparent-egress`: a client that ignores the
// proxy environment -- here raw Python sockets -- still reaches an
// allowlisted host through the filtered-egress proxy, via the fake
// resolver and the loopback listeners the supervisor-side helper binds
// inside the sandbox's network namespace.
//
// The fixture lives on host loopback, so these launches set the two
// undocumented test knobs on the OUTER ai-jail: AI_JAIL_TEST_PROXY_ALLOW_PRIVATE
// (the proxy may dial loopback) and AI_JAIL_TEST_TRANSPARENT_PORTS (a
// fixture cannot listen on 80/443 unprivileged).
//
// The in-sandbox name must be answered by nothing but the fake resolver:
// not /etc/hosts, and not NSS modules such as nss-myhostname, which
// resolve `localhost.localdomain` and `*.localhost` locally. A reserved
// `.test` name satisfies that, and a third knob,
// AI_JAIL_TEST_PROXY_LOOPBACK_NAME, makes the proxy resolve exactly that
// name to loopback -- so nothing here depends on the host's DNS setup.
//
// Linux-only; tests skip gracefully when bwrap or python3 is unavailable.
#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::{Mutex, OnceLock};

static SANDBOX_RUN_LOCK: Mutex<()> = Mutex::new(());

const NAME: &str = "fixture.ai-jail.test";

fn available() -> Result<(), &'static str> {
    static RESULT: OnceLock<Result<(), &'static str>> = OnceLock::new();
    *RESULT.get_or_init(|| {
        let ok = |mut c: Command| {
            c.output().map(|o| o.status.success()).unwrap_or(false)
        };
        let mut bwrap = Command::new("bwrap");
        bwrap.args([
            "--ro-bind",
            "/",
            "/",
            "--proc",
            "/proc",
            "--unshare-net",
            "--",
            "true",
        ]);
        if !ok(bwrap) {
            return Err("bwrap cannot create network namespaces");
        }
        let mut python = Command::new("python3");
        python.arg("--version");
        if !ok(python) {
            return Err("python3 not found");
        }
        Ok(())
    })
}

macro_rules! require {
    () => {
        if let Err(why) = available() {
            eprintln!("SKIPPED: {why}");
            return;
        }
    };
}

fn ai_jail() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ai-jail"))
}

/// HTTP fixture on host loopback answering `ok`.
fn http_fixture() -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for conn in listener.incoming().map_while(Result::ok) {
            std::thread::spawn(move || {
                let mut stream = conn;
                let mut buf = [0_u8; 4096];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
                );
            });
        }
    });
    port
}

/// A proxy-ignoring client: resolve with getaddrinfo, dial, GET.
fn client(name: &str, port: u16) -> String {
    format!(
        "import socket\n\
         try:\n    addr = socket.getaddrinfo('{name}', {port}, socket.AF_INET)[0][4]\n\
         except socket.gaierror:\n    print('NXDOMAIN'); raise SystemExit\n\
         s = socket.create_connection(addr, timeout=10)\n\
         s.sendall(b'GET / HTTP/1.0\\r\\nHost: x\\r\\n\\r\\n')\n\
         data = b''\n\
         while True:\n    c = s.recv(4096)\n    if not c: break\n    data += c\n\
         print('ADDR', addr[0]); print('BODY', data.split(b'\\r\\n\\r\\n')[-1].decode())\n"
    )
}

fn run(flags: &[&str], port: u16, script: &str) -> Output {
    let _lock = SANDBOX_RUN_LOCK.lock().unwrap();
    Command::new(ai_jail())
        .args(["--clean", "--no-status-bar", "--exec", "--no-save-config"])
        .args(flags)
        .env("AI_JAIL_TEST_PROXY_ALLOW_PRIVATE", "1")
        .env("AI_JAIL_TEST_TRANSPARENT_PORTS", port.to_string())
        .env("AI_JAIL_TEST_PROXY_LOOPBACK_NAME", NAME)
        .args(["python3", "-c", script])
        .output()
        .expect("failed to spawn ai-jail")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn proxy_ignoring_client_reaches_an_allowlisted_host() {
    require!();
    let port = http_fixture();
    let output = run(
        &["--allow-host", NAME, "--transparent-egress"],
        port,
        &client(NAME, port),
    );
    let out = stdout(&output);
    assert!(
        output.status.success(),
        "{out} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    // The client dialed a fake address, and the proxy delivered.
    assert!(out.contains("ADDR 127.64."), "{out}");
    assert!(out.contains("BODY ok"), "{out}");
}

#[test]
fn name_outside_the_allowlist_does_not_resolve() {
    require!();
    let port = http_fixture();
    let output = run(
        &["--allow-host", "example.invalid", "--transparent-egress"],
        port,
        &client(NAME, port),
    );
    assert_eq!(stdout(&output).trim(), "NXDOMAIN");
}

#[test]
fn without_the_flag_the_same_client_has_no_dns() {
    require!();
    let port = http_fixture();
    let output = run(&["--allow-host", NAME], port, &client(NAME, port));
    // Filtered egress alone: the proxy-ignoring client cannot resolve.
    assert_eq!(stdout(&output).trim(), "NXDOMAIN");
}

#[test]
fn agent_holds_no_capabilities_and_helper_does_not_outlive_the_launch() {
    require!();
    let port = http_fixture();
    let script = "print(open('/proc/self/status').read().split('CapEff:')[1].split()[0])";
    let output = run(
        &["--allow-host", NAME, "--transparent-egress"],
        port,
        script,
    );
    assert_eq!(stdout(&output).trim(), "0000000000000000");
    let marker = port.to_string();
    let survivors: Vec<_> = std::fs::read_dir("/proc")
        .unwrap()
        .filter_map(Result::ok)
        .filter_map(|e| std::fs::read(e.path().join("cmdline")).ok())
        .map(|c| String::from_utf8_lossy(&c).replace('\0', " "))
        .filter(|c| c.contains("--transparent-helper") && c.contains(&marker))
        .collect();
    assert!(
        survivors.is_empty(),
        "helper outlived the launch: {survivors:?}"
    );
}

#[test]
fn transparent_egress_requires_allow_host() {
    let output = Command::new(ai_jail())
        .args(["--clean", "--no-status-bar", "--exec", "--no-save-config"])
        .args(["--transparent-egress", "true"])
        .output()
        .expect("failed to spawn ai-jail");
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("needs --allow-host")
    );
}

#[test]
fn helper_mode_is_not_a_launch_option() {
    let output = Command::new(ai_jail())
        .args(["--transparent-helper", "1", "/tmp/x.sock", "443", "a.com"])
        .env_remove("AI_JAIL_TRANSPARENT_HELPER")
        .output()
        .expect("failed to spawn ai-jail");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("internal mode"));
}
