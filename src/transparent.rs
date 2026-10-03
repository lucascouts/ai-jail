//! Transparent egress (Linux, `--transparent-egress`): filtered egress for
//! clients that ignore `HTTPS_PROXY`.
//!
//! Filtered egress reaches only clients that honor the proxy environment.
//! A client with its own HTTP agent or raw sockets resolves DNS itself and
//! dials directly, and inside the private netns there is neither DNS nor a
//! route, so it simply fails. This module closes that gap without granting
//! the sandbox anything new:
//!
//! 1. The sandbox's `/etc/resolv.conf` names `127.0.0.53`. A fake resolver
//!    there answers each *allowlisted* name with a unique address from
//!    `127.64.0.0/10` and remembers the pair; everything else gets
//!    NXDOMAIN. Nothing is ever resolved for real inside the sandbox, so
//!    this adds no DNS channel: the only lookups made on the host are the
//!    proxy's, for allowlisted names, exactly as for a proxy-aware client.
//! 2. Listeners on `0.0.0.0:<port>` (80 and 443) receive the connection the
//!    client then makes to that fake address -- the whole of `127.0.0.0/8`
//!    is local on loopback. `getsockname()` on the accepted socket yields
//!    the fake address, which maps back to the name.
//! 3. The connection is handed to the unchanged egress proxy as
//!    `CONNECT name:port`. Allowlist, SSRF guard and DNS pinning stay where
//!    they were: on the host, in the proxy.
//!
//! Ports below 1024 need `CAP_NET_BIND_SERVICE` in the sandbox's network
//! namespace, which the sandboxed agent must never hold. So none of this
//! runs inside the sandbox. A supervisor-side helper process enters the
//! sandbox's user and network namespaces -- the invoking user owns that
//! user namespace, so it holds full capabilities there and nowhere else --
//! binds its sockets, drops every capability, and only then lets bwrap
//! start the agent (`--block-fd`). The helper keeps the host mount and pid
//! namespaces: it reaches the proxy's Unix socket by its host path, and the
//! sandbox cannot see, signal or trace it.

use std::collections::HashMap;
use std::io::{self, BufRead, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;

/// Address of the fake resolver inside the sandbox's network namespace.
pub(crate) const RESOLVER_ADDR: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 53);

/// Ports intercepted by default: plain HTTP and HTTPS.
pub(crate) const DEFAULT_PORTS: [u16; 2] = [80, 443];

/// Contents of the sandbox's `/etc/resolv.conf` in transparent mode.
pub(crate) const RESOLV_CONF: &str = "nameserver 127.0.0.53\n";

/// First and one-past-last host part of the fake range `127.64.0.0/10`.
const FAKE_FIRST: u32 = 0x7F40_0001;
const FAKE_END: u32 = 0x7F80_0000;

/// Most names one launch will map. The table lives in the helper, outside
/// the sandbox and beyond any limit on it, and every allowlist entry also
/// covers its subdomains: uncapped, 2 M distinct subdomains took the helper
/// to 1.15 GB. Past the cap new names get SERVFAIL; mapped names still work.
const MAX_FAKE_NAMES: usize = 65_536;

/// TTL on fake answers. Mappings live for the whole launch, so a long TTL
/// is safe; it only spares the resolver repeat queries.
const FAKE_TTL: u32 = 300;

/// Name <-> fake address table for one launch.
#[derive(Default)]
pub(crate) struct FakeDns {
    by_name: HashMap<String, Ipv4Addr>,
    by_addr: HashMap<Ipv4Addr, String>,
    next: u32,
}

impl FakeDns {
    /// The fake address for `name`, allocating one on first sight. `None`
    /// once the /10 is exhausted (four million names in one launch).
    pub(crate) fn addr_for(&mut self, name: &str) -> Option<Ipv4Addr> {
        if let Some(addr) = self.by_name.get(name) {
            return Some(*addr);
        }
        if self.by_name.len() >= MAX_FAKE_NAMES {
            return None;
        }
        let raw = FAKE_FIRST.checked_add(self.next)?;
        if raw >= FAKE_END {
            return None;
        }
        self.next += 1;
        let addr = Ipv4Addr::from(raw);
        self.by_name.insert(name.to_string(), addr);
        self.by_addr.insert(addr, name.to_string());
        Some(addr)
    }

    pub(crate) fn name_for(&self, addr: Ipv4Addr) -> Option<&str> {
        self.by_addr.get(&addr).map(String::as_str)
    }
}

const TYPE_A: u16 = 1;
const CLASS_IN: u16 = 1;
const RCODE_FORMERR: u8 = 1;
const RCODE_SERVFAIL: u8 = 2;
const RCODE_NXDOMAIN: u8 = 3;
const RCODE_NOTIMP: u8 = 4;

/// A parsed single-question query.
struct Question<'a> {
    id: [u8; 2],
    rd: bool,
    /// The question section exactly as received, for echoing back.
    raw: &'a [u8],
    name: String,
    qtype: u16,
    qclass: u16,
}

/// Parse a standard query with exactly one question. Compression pointers
/// are refused (a query has nothing to point back to), and the name must
/// be plain hostname characters: it becomes the host in a CONNECT line,
/// so nothing that could break that line may pass.
fn parse_query(packet: &[u8]) -> Result<Question<'_>, Option<[u8; 2]>> {
    if packet.len() < 12 {
        return Err(None);
    }
    let id = [packet[0], packet[1]];
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    let is_response = flags & 0x8000 != 0;
    let opcode = (flags >> 11) & 0xF;
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    if is_response || opcode != 0 || qdcount != 1 {
        return Err(Some(id));
    }
    let mut pos = 12;
    let mut labels: Vec<String> = Vec::new();
    let mut total = 0_usize;
    loop {
        let len = *packet.get(pos).ok_or(Some(id))? as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        if len > 63 {
            return Err(Some(id));
        }
        let label = packet.get(pos..pos + len).ok_or(Some(id))?;
        if !label
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
        {
            return Err(Some(id));
        }
        total += len + 1;
        if total > 253 {
            return Err(Some(id));
        }
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        pos += len;
    }
    let tail = packet.get(pos..pos + 4).ok_or(Some(id))?;
    let qtype = u16::from_be_bytes([tail[0], tail[1]]);
    let qclass = u16::from_be_bytes([tail[2], tail[3]]);
    Ok(Question {
        id,
        rd: flags & 0x0100 != 0,
        raw: &packet[12..pos + 4],
        name: labels.join("."),
        qtype,
        qclass,
    })
}

fn header(id: [u8; 2], rd: bool, rcode: u8, qd: u16, an: u16) -> Vec<u8> {
    let mut flags: u16 = 0x8000 | 0x0400 | 0x0080; // QR, AA, RA
    if rd {
        flags |= 0x0100;
    }
    flags |= u16::from(rcode);
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&id);
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&qd.to_be_bytes());
    out.extend_from_slice(&an.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out
}

/// Answer one query packet. An allowlisted name gets its fake A record,
/// and NODATA for any other type (AAAA included, so clients fall back to
/// IPv4). A name outside the allowlist gets NXDOMAIN: it would be refused
/// by the proxy anyway, and failing at resolution is faster and clearer.
/// Malformed packets get FORMERR when they carry an id, silence otherwise.
pub(crate) fn answer(
    packet: &[u8],
    allowlist: &[String],
    table: &Mutex<FakeDns>,
) -> Option<Vec<u8>> {
    let q = match parse_query(packet) {
        Ok(q) => q,
        Err(Some(id)) => return Some(header(id, false, RCODE_FORMERR, 0, 0)),
        Err(None) => return None,
    };
    if q.qclass != CLASS_IN {
        let mut out = header(q.id, q.rd, RCODE_NOTIMP, 1, 0);
        out.extend_from_slice(q.raw);
        return Some(out);
    }
    if q.name.is_empty() || !crate::proxy::allowlist_matches(allowlist, &q.name)
    {
        let mut out = header(q.id, q.rd, RCODE_NXDOMAIN, 1, 0);
        out.extend_from_slice(q.raw);
        return Some(out);
    }
    let addr = if q.qtype == TYPE_A {
        let addr = table.lock().ok()?.addr_for(&q.name);
        if addr.is_none() {
            // Table full: fail this name instead of growing without bound.
            let mut out = header(q.id, q.rd, RCODE_SERVFAIL, 1, 0);
            out.extend_from_slice(q.raw);
            return Some(out);
        }
        addr
    } else {
        None
    };
    let mut out = header(q.id, q.rd, 0, 1, u16::from(addr.is_some()));
    out.extend_from_slice(q.raw);
    if let Some(addr) = addr {
        out.extend_from_slice(&[0xC0, 0x0C]); // pointer to the question name
        out.extend_from_slice(&TYPE_A.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&FAKE_TTL.to_be_bytes());
        out.extend_from_slice(&4_u16.to_be_bytes());
        out.extend_from_slice(&addr.octets());
    }
    Some(out)
}

/// Open a CONNECT tunnel to `name:port` through the proxy's Unix socket.
/// Returns the stream positioned right after the proxy's header block.
fn open_tunnel(proxy: &Path, name: &str, port: u16) -> io::Result<UnixStream> {
    let mut upstream = UnixStream::connect(proxy)?;
    let request = format!(
        "CONNECT {name}:{port} HTTP/1.1\r\nHost: {name}:{port}\r\n\r\n"
    );
    upstream.write_all(request.as_bytes())?;
    // Read the reply byte by byte: nothing past the header block may be
    // consumed here, or it would be lost to the relay.
    let mut head = Vec::with_capacity(128);
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 8192 || upstream.read(&mut byte)? == 0 {
            return Err(io::Error::other("proxy closed before its reply"));
        }
        head.push(byte[0]);
    }
    let status = head.split(|b| *b == b' ').nth(1).unwrap_or_default();
    if status != b"200" {
        return Err(io::Error::other("proxy refused the tunnel"));
    }
    Ok(upstream)
}

fn serve_listener(
    listener: TcpListener,
    proxy: PathBuf,
    table: Arc<Mutex<FakeDns>>,
) {
    for client in listener.incoming() {
        // A failed accept (EMFILE, ECONNABORTED) is transient: pause and go
        // on, never end the listener for the rest of the launch.
        let Ok(client) = client else {
            thread::sleep(std::time::Duration::from_millis(50));
            continue;
        };
        let proxy = proxy.clone();
        let table = Arc::clone(&table);
        thread::spawn(move || {
            let Ok(SocketAddr::V4(local)) = client.local_addr() else {
                return;
            };
            let name = match table.lock() {
                Ok(t) => t.name_for(*local.ip()).map(str::to_string),
                Err(_) => None,
            };
            // Only addresses this resolver handed out lead anywhere.
            let Some(name) = name else {
                return;
            };
            if let Ok(upstream) = open_tunnel(&proxy, &name, local.port()) {
                crate::proxy::relay(client, upstream);
            }
        });
    }
}

fn serve_resolver(
    socket: UdpSocket,
    allowlist: Vec<String>,
    table: Arc<Mutex<FakeDns>>,
) {
    let mut buf = [0_u8; 512];
    loop {
        let Ok((n, peer)) = socket.recv_from(&mut buf) else {
            thread::sleep(std::time::Duration::from_millis(50));
            continue;
        };
        if let Some(reply) = answer(&buf[..n], &allowlist, &table) {
            let _ = socket.send_to(&reply, peer);
        }
    }
}

/// `ioctl(2)` request returning the user namespace that owns a namespace fd
/// (`NS_GET_USERNS`, linux/nsfs.h: `_IO(0xb7, 0x1)`).
const NS_GET_USERNS: u64 = 0xb701;

/// Join the network namespace of process `pid`, entering first the user
/// namespace that *owns* it. Must run while the process is still
/// single-threaded: joining a user namespace is refused to a
/// multi-threaded caller.
///
/// The owner is asked of the kernel rather than read from
/// `/proc/<pid>/ns/user`, because that path races: bwrap reports the pid,
/// then moves the child into a nested user namespace of its own. Read
/// after that move, `/proc/<pid>/ns/user` names the nested namespace,
/// which has no authority over the network namespace (measured: 4 of 40
/// launches failed with EPERM). The network namespace itself never
/// changes, and neither does its owner.
fn enter_namespaces(pid: u32) -> Result<(), String> {
    use nix::sched::{CloneFlags, setns};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::fs::MetadataExt;

    let path = format!("/proc/{pid}/ns/net");
    let net = std::fs::File::open(&path)
        .map_err(|e| format!("cannot open {path}: {e}"))?;
    // Never bind on the host: a sandbox that somehow shares our network
    // namespace is refused, not served.
    let ours = std::fs::metadata("/proc/self/ns/net")
        .map_err(|e| format!("cannot read our own net namespace: {e}"))?;
    let theirs = net
        .metadata()
        .map_err(|e| format!("cannot stat {path}: {e}"))?;
    if (theirs.dev(), theirs.ino()) == (ours.dev(), ours.ino()) {
        return Err("the sandbox shares the host network namespace".into());
    }
    // SAFETY: NS_GET_USERNS takes no argument and returns a new fd, which
    // is immediately wrapped in an OwnedFd.
    let raw = unsafe { nix::libc::ioctl(net.as_raw_fd(), NS_GET_USERNS as _) };
    if raw < 0 {
        return Err(format!(
            "cannot find the owner of the sandbox net namespace: {}",
            io::Error::last_os_error()
        ));
    }
    // SAFETY: `raw` is a fresh, valid fd owned by nothing else.
    let owner = unsafe { OwnedFd::from_raw_fd(raw) };
    setns(&owner, CloneFlags::CLONE_NEWUSER)
        .map_err(|e| format!("cannot join the sandbox user namespace: {e}"))?;
    setns(&net, CloneFlags::CLONE_NEWNET)
        .map_err(|e| format!("cannot join the sandbox net namespace: {e}"))?;
    Ok(())
}

/// How long to wait for the sandbox's loopback to come up.
const LOOPBACK_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// Bind the resolver on `127.0.0.53:53`, waiting for loopback. bwrap
/// brings `lo` up in the child during setup, which runs concurrently with
/// the helper joining the namespace: a helper that arrives first finds no
/// 127.0.0.0/8 address yet and gets EADDRNOTAVAIL (measured: 2 of 60
/// launches). bwrap does it before blocking on `--block-fd`, so the wait
/// is bounded; bringing `lo` up here instead would race bwrap's own
/// address setup. The listeners bind the wildcard address and need no wait.
fn bind_resolver() -> Result<UdpSocket, String> {
    let deadline = std::time::Instant::now() + LOOPBACK_WAIT;
    loop {
        match UdpSocket::bind((RESOLVER_ADDR, 53)) {
            Ok(socket) => return Ok(socket),
            Err(e)
                if e.kind() == io::ErrorKind::AddrNotAvailable
                    && std::time::Instant::now() < deadline =>
            {
                thread::sleep(std::time::Duration::from_millis(5));
            }
            Err(e) => {
                return Err(format!(
                    "cannot bind the resolver on {RESOLVER_ADDR}:53: {e}"
                ));
            }
        }
    }
}

/// Drop every capability in every set and forbid regaining any. The helper
/// needs its capabilities only to bind; everything after is plain I/O.
fn drop_all_capabilities() -> Result<(), String> {
    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
    // Bounding set first, while CAP_SETPCAP is still held. Unknown
    // capability numbers above the kernel's last one return EINVAL; stop
    // there.
    for cap in 0..64 {
        // SAFETY: prctl with integer arguments.
        if unsafe { nix::libc::prctl(nix::libc::PR_CAPBSET_DROP, cap, 0, 0, 0) }
            != 0
        {
            if io::Error::last_os_error().raw_os_error()
                == Some(nix::libc::EINVAL)
            {
                break;
            }
            return Err(format!(
                "cannot drop capability {cap} from the bounding set: {}",
                io::Error::last_os_error()
            ));
        }
    }
    let mut header = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: capset(2) with a v3 header and two data words, both valid
    // for the duration of the call.
    let rc = unsafe {
        nix::libc::syscall(
            nix::libc::SYS_capset,
            &mut header as *mut CapHeader,
            data.as_ptr(),
        )
    };
    if rc != 0 {
        return Err(format!(
            "cannot drop capabilities: {}",
            io::Error::last_os_error()
        ));
    }
    // SAFETY: plain prctl call with integer arguments.
    if unsafe { nix::libc::prctl(nix::libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) }
        != 0
    {
        return Err(format!(
            "cannot set no_new_privs: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Deny the helper every filesystem access (Landlock, best effort). Once
/// bound it only relays bytes, yet it parses input the sandbox controls
/// while running as the user; this takes the user's files out of reach of
/// any bug in that parsing. Connecting to the proxy's Unix socket by path
/// is not a Landlock filesystem right, so the relay keeps working. A
/// kernel without Landlock leaves the helper as it was.
fn deny_filesystem() {
    use landlock::{ABI, Access, AccessFs, Ruleset, RulesetAttr};
    let _ = Ruleset::default()
        .handle_access(AccessFs::from_all(ABI::V3))
        .and_then(|r| r.create())
        .and_then(|r| r.restrict_self());
}

/// Internal mode `--transparent-helper`: join the sandbox of `pid`, bind
/// the resolver and the listeners, drop every capability, report `ready`
/// on stdout, then serve until stdin closes -- the supervisor holds the
/// other end, so the helper never outlives it.
pub(crate) fn run_helper(
    pid: u32,
    proxy: &Path,
    ports: &[u16],
    allowlist: Vec<String>,
) -> Result<(), String> {
    enter_namespaces(pid)?;
    let resolver = bind_resolver()?;
    let mut listeners = Vec::new();
    for &port in ports {
        let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, port))
            .map_err(|e| format!("cannot listen on port {port}: {e}"))?;
        listeners.push(listener);
    }
    drop_all_capabilities()?;
    deny_filesystem();

    let table = Arc::new(Mutex::new(FakeDns::default()));
    {
        let table = Arc::clone(&table);
        thread::spawn(move || serve_resolver(resolver, allowlist, table));
    }
    for listener in listeners {
        let proxy = proxy.to_path_buf();
        let table = Arc::clone(&table);
        thread::spawn(move || serve_listener(listener, proxy, table));
    }

    let mut stdout = io::stdout();
    stdout
        .write_all(b"ready\n")
        .and_then(|()| stdout.flush())
        .map_err(|e| format!("cannot report readiness: {e}"))?;
    // Serve until the supervisor goes away (EOF), however it goes.
    let mut sink = Vec::new();
    let _ = io::stdin().lock().read_until(b'\n', &mut sink);
    let _ = io::stdin().read_to_end(&mut sink);
    Ok(())
}

/// Supervisor side of one launch: the pipes bwrap reports and blocks on,
/// and the helper once started. Dropping it stops the helper.
pub(crate) struct Transparent {
    info_reader: Option<io::PipeReader>,
    info_writer: Option<io::PipeWriter>,
    block_reader: Option<io::PipeReader>,
    block_writer: Option<io::PipeWriter>,
    resolv: PathBuf,
    helper: Arc<Mutex<Option<std::process::Child>>>,
}

impl Transparent {
    /// Create the pipes and the sandbox's resolv.conf. Nothing runs yet.
    pub(crate) fn prepare() -> Result<Transparent, String> {
        let (info_reader, info_writer) = io::pipe()
            .map_err(|e| format!("cannot create the info pipe: {e}"))?;
        let (block_reader, block_writer) = io::pipe()
            .map_err(|e| format!("cannot create the block pipe: {e}"))?;
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let resolv = std::env::temp_dir()
            .join(format!("ai-jail-resolv.{}.{nonce}", std::process::id()));
        {
            use std::os::unix::fs::OpenOptionsExt;
            // create_new: never reuse, never follow what is already there.
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&resolv)
                .and_then(|mut f| f.write_all(RESOLV_CONF.as_bytes()))
                .map_err(|e| {
                    format!("cannot write the sandbox resolv.conf: {e}")
                })?;
        }
        Ok(Transparent {
            info_reader: Some(info_reader),
            info_writer: Some(info_writer),
            block_reader: Some(block_reader),
            block_writer: Some(block_writer),
            resolv,
            helper: Arc::new(Mutex::new(None)),
        })
    }

    /// What bwrap needs: the fds it inherits and the resolv.conf source.
    pub(crate) fn launch_fds(&self) -> crate::sandbox::TransparentFds<'_> {
        use std::os::fd::AsRawFd;
        crate::sandbox::TransparentFds {
            info_fd: self.info_writer.as_ref().map_or(-1, AsRawFd::as_raw_fd),
            block_fd: self.block_reader.as_ref().map_or(-1, AsRawFd::as_raw_fd),
            resolv: &self.resolv,
        }
    }

    /// Call right before bwrap is spawned (either spawn path): on a
    /// background thread, wait for bwrap to report the sandbox pid, start
    /// the helper, and release bwrap once the helper is ready. If the
    /// helper fails, the sandbox is killed before the agent ever runs -- a
    /// launch that asked for transparent egress never silently runs
    /// without it. Our copies of bwrap's ends stay open until drop: the
    /// pid is parsed without waiting for EOF, and a reader we never read
    /// from does not steal the release byte.
    pub(crate) fn activate(
        &mut self,
        proxy: PathBuf,
        ports: Vec<u16>,
        allowlist: Vec<String>,
    ) {
        let (Some(info), Some(block)) =
            (self.info_reader.take(), self.block_writer.take())
        else {
            return;
        };
        let helper = Arc::clone(&self.helper);
        thread::spawn(move || {
            let pid = match read_child_pid(info) {
                Ok(pid) => pid,
                Err(e) => {
                    // No pid, so nothing to kill: bwrap itself has failed
                    // or died. Were the sandbox to start anyway it would be
                    // plain filtered egress with no resolver -- no egress
                    // for proxy-ignoring clients, never more than asked.
                    crate::output::security_warn(&format!(
                        "transparent egress: {e}"
                    ));
                    return;
                }
            };
            match start_helper(pid, &proxy, &ports, &allowlist) {
                Ok(child) => {
                    if let Ok(mut slot) = helper.lock() {
                        *slot = Some(child);
                    }
                    let mut block = block;
                    let _ = block.write_all(b"1");
                }
                Err(e) => {
                    crate::output::security_warn(&format!(
                        "transparent egress failed, stopping the sandbox: {e}"
                    ));
                    // SAFETY: kill(2) on the sandbox's init pid.
                    unsafe {
                        nix::libc::kill(pid as i32, nix::libc::SIGKILL);
                    }
                }
            }
        });
    }
}

impl Drop for Transparent {
    fn drop(&mut self) {
        if let Ok(mut slot) = self.helper.lock()
            && let Some(mut child) = slot.take()
        {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = std::fs::remove_file(&self.resolv);
    }
}

/// bwrap writes `{ "child-pid": N, ... }` to its info fd once the sandbox
/// namespaces exist.
fn read_child_pid(mut info: io::PipeReader) -> Result<u32, String> {
    let mut buf = Vec::new();
    let mut chunk = [0_u8; 256];
    loop {
        let n = info
            .read(&mut chunk)
            .map_err(|e| format!("cannot read bwrap's info fd: {e}"))?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&buf)
            && let Some(pid) = value.get("child-pid").and_then(|v| v.as_u64())
        {
            // 0 would signal our own process group, and anything that does
            // not fit a pid_t is not a pid.
            return u32::try_from(pid)
                .ok()
                .filter(|&p| p > 1 && i32::try_from(p).is_ok())
                .ok_or_else(|| {
                    format!("bwrap reported an invalid pid: {pid}")
                });
        }
    }
    Err("bwrap reported no sandbox pid".into())
}

fn start_helper(
    pid: u32,
    proxy: &Path,
    ports: &[u16],
    allowlist: &[String],
) -> Result<std::process::Child, String> {
    use std::process::{Command, Stdio};
    let exe = std::env::current_exe()
        .map_err(|e| format!("cannot resolve the ai-jail binary: {e}"))?;
    let mut command = Command::new(exe);
    command
        .arg("--transparent-helper")
        .arg(pid.to_string())
        .arg(proxy)
        .arg(
            ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(","),
        );
    // `--` ends the helper's options, and only hostname-shaped entries are
    // passed at all: the resolver can only ever match `[A-Za-z0-9._-]`
    // names, and an entry starting with `-` must never read as a flag.
    command.arg("--");
    command.args(helper_hosts(allowlist));
    let mut child = command
        .env(HELPER_MARKER, "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("cannot start the helper: {e}"))?;
    let mut line = String::new();
    let ready = child
        .stdout
        .take()
        .map(|out| io::BufReader::new(out).read_line(&mut line))
        .is_some_and(|r| r.is_ok());
    if ready && line.trim() == "ready" {
        Ok(child)
    } else {
        let _ = child.kill();
        let _ = child.wait();
        Err("the helper did not come up".into())
    }
}

/// Allowlist entries worth passing to the helper: hostname-shaped ones.
/// The resolver can only ever match `[A-Za-z0-9._-]` names, and an entry
/// starting with `-` must never be read as one of the helper's flags.
fn helper_hosts(allowlist: &[String]) -> impl Iterator<Item = &String> {
    allowlist.iter().filter(|host| {
        !host.is_empty()
            && !host.starts_with('-')
            && host.bytes().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')
            })
    })
}

/// Env marker the internal helper mode refuses to run without.
pub(crate) const HELPER_MARKER: &str = "AI_JAIL_TRANSPARENT_HELPER";

#[cfg(test)]
mod tests {
    use super::*;

    fn query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut q = Vec::new();
        q.extend_from_slice(&id.to_be_bytes());
        q.extend_from_slice(&0x0100_u16.to_be_bytes()); // RD
        q.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
        for label in name.split('.').filter(|l| !l.is_empty()) {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&CLASS_IN.to_be_bytes());
        q
    }

    fn allow(hosts: &[&str]) -> Vec<String> {
        hosts.iter().map(|h| (*h).to_string()).collect()
    }

    fn rcode(reply: &[u8]) -> u8 {
        reply[3] & 0x0F
    }

    fn answers(reply: &[u8]) -> u16 {
        u16::from_be_bytes([reply[6], reply[7]])
    }

    #[test]
    fn allowlisted_name_gets_a_stable_fake_address() {
        let table = Mutex::new(FakeDns::default());
        let allowlist = allow(&["laratranslate.com"]);
        let reply = answer(
            &query(7, "api.laratranslate.com", TYPE_A),
            &allowlist,
            &table,
        )
        .unwrap();
        assert_eq!(&reply[..2], &7_u16.to_be_bytes());
        assert_eq!(rcode(&reply), 0);
        assert_eq!(answers(&reply), 1);
        let addr = Ipv4Addr::new(
            reply[reply.len() - 4],
            reply[reply.len() - 3],
            reply[reply.len() - 2],
            reply[reply.len() - 1],
        );
        assert_eq!(addr, Ipv4Addr::new(127, 64, 0, 1));
        // Same name, same address; the mapping reverses.
        let again = answer(
            &query(8, "API.LaraTranslate.com", TYPE_A),
            &allowlist,
            &table,
        )
        .unwrap();
        assert_eq!(&again[again.len() - 4..], &addr.octets());
        assert_eq!(
            table.lock().unwrap().name_for(addr),
            Some("api.laratranslate.com")
        );
    }

    #[test]
    fn name_outside_the_allowlist_is_nxdomain() {
        let table = Mutex::new(FakeDns::default());
        let reply = answer(
            &query(1, "evil.com", TYPE_A),
            &allow(&["laratranslate.com"]),
            &table,
        )
        .unwrap();
        assert_eq!(rcode(&reply), RCODE_NXDOMAIN);
        assert_eq!(answers(&reply), 0);
        assert!(table.lock().unwrap().by_name.is_empty());
    }

    #[test]
    fn aaaa_for_an_allowed_name_is_nodata() {
        let table = Mutex::new(FakeDns::default());
        let reply = answer(
            &query(1, "example.com", 28),
            &allow(&["example.com"]),
            &table,
        )
        .unwrap();
        assert_eq!(rcode(&reply), 0);
        assert_eq!(answers(&reply), 0);
    }

    #[test]
    fn names_that_could_break_a_connect_line_are_refused() {
        let table = Mutex::new(FakeDns::default());
        let allowlist = allow(&["example.com"]);
        for bad in [
            b"a b".as_slice(),
            b"a\r\nb".as_slice(),
            b"a:1".as_slice(),
            b"a/b".as_slice(),
        ] {
            let mut q = query(9, "x", TYPE_A);
            // Replace the single label "x" with the raw bad label.
            q.truncate(12);
            q.push(bad.len() as u8);
            q.extend_from_slice(bad);
            q.extend_from_slice(&[3, b'c', b'o', b'm', 0]);
            q.extend_from_slice(&TYPE_A.to_be_bytes());
            q.extend_from_slice(&CLASS_IN.to_be_bytes());
            let reply = answer(&q, &allowlist, &table).unwrap();
            assert_eq!(rcode(&reply), RCODE_FORMERR, "{bad:?}");
        }
        assert!(table.lock().unwrap().by_name.is_empty());
    }

    #[test]
    fn malformed_packets_never_panic() {
        let table = Mutex::new(FakeDns::default());
        let allowlist = allow(&["example.com"]);
        assert!(answer(&[], &allowlist, &table).is_none());
        assert!(answer(&[0; 11], &allowlist, &table).is_none());
        let mut truncated = query(3, "example.com", TYPE_A);
        truncated.truncate(truncated.len() - 3);
        assert_eq!(
            rcode(&answer(&truncated, &allowlist, &table).unwrap()),
            RCODE_FORMERR
        );
        // A compression pointer in a query is refused, not followed.
        let mut pointer = query(4, "", TYPE_A);
        pointer.truncate(12);
        pointer.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1]);
        assert_eq!(
            rcode(&answer(&pointer, &allowlist, &table).unwrap()),
            RCODE_FORMERR
        );
        // Every prefix of a valid query parses or fails cleanly.
        let full = query(5, "api.example.com", TYPE_A);
        for end in 0..full.len() {
            let _ = answer(&full[..end], &allowlist, &table);
        }
    }

    #[test]
    fn helper_receives_only_hostname_shaped_entries() {
        let allowlist = allow(&[
            "api.anthropic.com",
            "-x",
            "--no-gpu",
            "2606:4700::1111",
            "93.184.216.34",
            "under_score.example",
            "",
        ]);
        let passed: Vec<_> = helper_hosts(&allowlist).collect();
        assert_eq!(
            passed,
            vec!["api.anthropic.com", "93.184.216.34", "under_score.example"]
        );
    }

    #[test]
    fn name_table_is_capped_and_answers_servfail_past_it() {
        let mut full = FakeDns::default();
        for i in 0..MAX_FAKE_NAMES {
            assert!(full.addr_for(&format!("n{i}.example.com")).is_some());
        }
        assert!(full.addr_for("one-more.example.com").is_none());
        // Names mapped before the cap keep resolving.
        assert!(full.addr_for("n7.example.com").is_some());
        let table = Mutex::new(full);
        let reply = answer(
            &query(9, "fresh.example.com", TYPE_A),
            &allow(&["example.com"]),
            &table,
        )
        .unwrap();
        assert_eq!(rcode(&reply), RCODE_SERVFAIL);
        assert_eq!(answers(&reply), 0);
    }

    #[test]
    fn fake_range_is_bounded() {
        let mut table = FakeDns {
            next: FAKE_END - FAKE_FIRST - 1,
            ..FakeDns::default()
        };
        assert_eq!(
            table.addr_for("last.example"),
            Some(Ipv4Addr::from(FAKE_END - 1))
        );
        assert_eq!(table.addr_for("one.too.many"), None);
        // An already-mapped name still resolves after exhaustion.
        assert!(table.addr_for("last.example").is_some());
    }
}
