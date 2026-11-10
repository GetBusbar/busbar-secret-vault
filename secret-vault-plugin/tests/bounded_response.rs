// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The actual Vault door over the production connector and HTTP framer. An unfinished response
//! must respect the body cap and whole-exchange deadline.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use busbar_contract::abi::mechanism::call::{
    Blob, InHead, OutHead, BLOB_JSON, BLOB_OCTETS, BLOB_SECRET,
};
use busbar_contract::abi::mechanism::call::{DeadlineClass, Outcome};
use busbar_contract::abi::mechanism::lifecycle::{self as life, OpenIn, OpenOut, ValidateIn};
use busbar_contract::abi::secret::{self, ResolveIn, ResolveOut};
use busbar_plugin_loader::dispatch::kinds::secret::Secret;
use busbar_plugin_loader::dispatch::{
    in_head, load_dropped, load_linked, out_head, rendering_of_library, Bind, ConnTable,
    Dispatcher, LinkedRow, NoSink, Plugin, NO_BLOB,
};
use busbar_plugin_loader::dispatch::{Called, Frame};

#[derive(Clone, Copy)]
enum Leg {
    Linked,
    Dropped,
}

fn json(bytes: &[u8]) -> Blob {
    Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt: BLOB_JSON,
        flags: 0,
    }
}

/// Refuses any credential that crosses a metric label or a diagnostic.
struct AuditSink;
fn clean(bytes: &[u8]) {
    for credential in [
        TOKEN.as_bytes(),
        MATERIAL,
        b"s.conformance-token",
        b"sk-conformance",
    ] {
        assert!(
            !bytes
                .windows(credential.len())
                .any(|part| part == credential),
            "credential crossed an error/log boundary"
        );
    }
}
impl busbar_plugin_loader::dispatch::EnvelopeSink for AuditSink {
    fn metric(&self, metric: busbar_plugin_loader::dispatch::Metric<'_>) {
        for label in metric.labels {
            clean(label);
        }
    }
    fn diag(&self, diagnostic: busbar_plugin_loader::dispatch::Diagnostic<'_>) {
        clean(diagnostic.name);
        clean(diagnostic.text);
    }
    fn dropped(&self, _: busbar_plugin_loader::dispatch::Dropped) {}
}
fn checked_call<
    I: busbar_plugin_loader::dispatch::InFrame,
    O: busbar_plugin_loader::dispatch::OutFrame,
>(
    plugin: &Plugin<Secret>,
    operation: u32,
    frame: &mut Frame<I, O>,
) -> Called {
    let before = plugin.test_invocations().0;
    let resumes = plugin.test_invocations().1;
    let called = plugin.call(operation, frame);
    if let Some(error) = &called.error {
        clean(error);
    }
    let ca_preflight = matches!(operation, life::slot::OPEN | life::slot::REFRESH)
        && called.outcome == Outcome::Failed
        && called.error.as_deref().is_some_and(|reason| {
            reason.starts_with(
                b"settings.ca_cert_pem: the host refused the CA certificate it names for need ",
            )
        });
    let refused_before_crossing = (operation == life::slot::OPEN
        && matches!(called.outcome, Outcome::Refused | Outcome::Fault))
        || ca_preflight;
    assert_eq!(
        plugin.test_invocations().0 - before,
        u64::from(!refused_before_crossing),
        "lifecycle slot {operation} outcome {:?}, sanitized reason {:?}",
        called.outcome,
        called.error.as_deref().map(String::from_utf8_lossy)
    );
    assert_eq!(plugin.test_invocations().1 - resumes, 0);
    if let Some(error) = &called.error {
        clean(error);
    }
    called
}

fn plugin(d: &Dispatcher, leg: Leg, instance: &str) -> Plugin<Secret> {
    plugin_with_trust(d, leg, instance, None)
}

fn plugin_with_trust(
    d: &Dispatcher,
    leg: Leg,
    instance: &str,
    anchors: Option<&str>,
) -> Plugin<Secret> {
    let bind = Bind {
        instance: Arc::from(instance),
        max_inflight_cap: 1024,
        sink: Arc::new(AuditSink),
        dispatcher: d.adopter(),
        conns: ConnTable::Host(
            busbar_contract::conn::admissions::AdmissionAuthority::issue(
                &busbar_contract::caps::KernelSeal::acquire_for_kernel(),
                host(d.conn_waker(), anchors, false),
                busbar_contract::secret_ref::Sugars::default(),
            ),
        ),
    };
    match leg {
        Leg::Linked => load_linked::<Secret>(
            &LinkedRow::of(busbar_secret_vault::door).expect("real row states"),
            bind,
        ),
        Leg::Dropped => {
            let path =
                std::path::PathBuf::from(std::env::var_os("BUSBAR_PLUGIN_CDYLIB").expect(
                    "build the dropped-in Vault cdylib freshly and set BUSBAR_PLUGIN_CDYLIB",
                ));
            assert!(
                path.is_absolute() && path.is_file(),
                "fresh absolute cdylib path required: {path:?}"
            );
            let stated = rendering_of_library(&path)
                .expect("real image renders")
                .expect("real image exports its door");
            load_dropped::<Secret>(&path, &stated, bind)
        }
    }
    .expect("load the real Vault door")
}

fn open(plugin: &Plugin<Secret>, settings: &[u8]) -> Called {
    let token = Blob {
        ptr: TOKEN.as_ptr(),
        len: TOKEN.len(),
        fmt: BLOB_OCTETS,
        flags: BLOB_SECRET,
    };
    let mut f = Frame::new(
        OpenIn {
            head: in_head(),
            host: std::ptr::null(),
            settings: json(settings),
            secrets: &token,
            secrets_len: 1,
            generation: 1,
            err_buf: std::ptr::null_mut(),
            err_cap: 0,
        },
        OpenOut {
            head: out_head(),
            instance: std::ptr::null_mut(),
            err_len: 0,
        },
    );
    checked_call(plugin, life::slot::OPEN, &mut f)
}

fn validate(plugin: &Plugin<Secret>, settings: &[u8]) -> Called {
    let mut reason = [0u8; 512];
    let mut f: Frame<ValidateIn, OutHead> = Frame::new(
        ValidateIn {
            head: in_head(),
            settings: json(settings),
            err_buf: reason.as_mut_ptr(),
            err_cap: reason.len(),
        },
        out_head(),
    );
    checked_call(plugin, life::slot::VALIDATE, &mut f)
}

fn close(plugin: &Plugin<Secret>) -> Called {
    let mut f: Frame<InHead, OutHead> = Frame::new(in_head(), out_head());
    checked_call(plugin, life::slot::CLOSE, &mut f)
}

const TOKEN: &str = "s.vault-bounded-response-token";
const MATERIAL: &[u8] = b"bounded-material";
const RESOLVE_CAP: usize = 128;

const HTTP_OK: u16 = 200;

// The production service provider reads the same monotonic clock as ticket deadlines.
fn dispatcher() -> Arc<Dispatcher> {
    Arc::new(Dispatcher::with_services(
        Default::default(),
        Arc::new(
            busbar_kernel::host_services::KernelServices::new()
                .with_mono_clock(Arc::new(busbar_plugin_loader::dispatch::now_ns)),
        ),
        busbar_contract::services::test_caller_binding(),
    ))
}

// Bind the production connector to the actual carrier and HTTP framer. This setup serves only
// this file's loopback response servers; it contains no transport implementation or TLS fixture.
fn host(
    wake: busbar_contract::conn::ConnWake,
    anchors: Option<&str>,
    guarded: bool,
) -> Arc<dyn busbar_contract::conn::DeclaredConns> {
    use busbar_contract::transport::{EgressTrust, TransportSettings};
    use busbar_core_connector::doors::Dispatched;
    use busbar_core_connector::registry::{Entry, Transports};
    use busbar_core_connector::{Connector, Judged, Verdict};
    use busbar_plugin_loader::dispatch::kinds::transport::Transport;
    use std::net::{SocketAddr, ToSocketAddrs};
    use std::sync::OnceLock;

    static IO: OnceLock<tokio::runtime::Handle> = OnceLock::new();
    let io = IO
        .get_or_init(|| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("response test reactor");
            let handle = rt.handle().clone();
            std::thread::spawn(move || rt.block_on(std::future::pending::<()>()));
            handle
        })
        .clone();
    busbar_core_connector::io::install_process_reactor(io.clone());
    static TRANSPORT_DISPATCHER: OnceLock<Arc<Dispatcher>> = OnceLock::new();
    let transport_dispatcher = Arc::clone(TRANSPORT_DISPATCHER.get_or_init(|| {
        // Request-head preparation runs here too, so the transport dispatcher needs the
        // production host clock, just as the outer Vault dispatcher does.
        let dispatcher = dispatcher();
        dispatcher.install_runtime(io);
        dispatcher.install_io(busbar_core_connector::hostio::process());
        dispatcher
    }));
    let mut entries = Vec::new();
    // The transport fixtures may pin an older SDK. Enter their published raw ABI, exactly
    // as a dropped image does, instead of requiring Rust types from two revisions to match.
    // Both functions return the actual static macro-built doors; the loader checks their ABI.
    extern "C" fn tcp_door() -> *const busbar_contract::abi::mechanism::door::Door {
        std::ptr::from_ref(busbar_transport_tcp::linked::door()).cast()
    }
    extern "C" fn http_door() -> *const busbar_contract::abi::mechanism::door::Door {
        std::ptr::from_ref(busbar_transport_http::door()).cast()
    }
    let drivers: [(&str, busbar_contract::abi::sdk::door::RawDoorFn); 2] =
        [("tcp", tcp_door), ("http", http_door)];
    for (name, door) in drivers {
        let row = LinkedRow::of_raw(door).expect("actual transport row states");
        let transport = load_linked::<Transport>(
            &row,
            Bind {
                instance: Arc::from(name),
                max_inflight_cap: 1024,
                sink: Arc::new(NoSink),
                dispatcher: transport_dispatcher.adopter(),
                conns: ConnTable::NoNeeds,
            },
        )
        .expect("actual transport loads");
        entries.push(Entry {
            door: Arc::new(
                Dispatched::open_on(
                    transport,
                    &TransportSettings::default(),
                    Arc::clone(&transport_dispatcher),
                )
                .expect("actual transport opens"),
            ),
            alpn: Vec::new(),
        });
    }
    let view = Transports::new(entries).expect("TCP and HTTP compose");
    let trust = EgressTrust {
        extra_anchors: anchors
            .map(|pem| {
                use rustls::pki_types::pem::PemObject;
                rustls::pki_types::CertificateDer::pem_slice_iter(pem.as_bytes())
                    .map(|certificate| certificate.expect("local CA PEM").to_vec())
                    .collect()
            })
            .unwrap_or_default(),
        ..Default::default()
    };
    let tls =
        busbar_core_connector::tls::client::build_client_config(&trust).expect("client TLS builds");
    let judge = |dest: &str, _: u32, _: Judged| -> Option<Result<SocketAddr, Verdict>> {
        Some(
            dest.to_socket_addrs()
                .ok()
                .and_then(|mut addresses| addresses.find(|a| a.ip().is_loopback()))
                .ok_or(busbar_contract::abi::host::service::DEST_UNRESOLVABLE),
        )
    };
    let judge: Arc<dyn busbar_core_connector::DialJudge> = if guarded {
        let config = busbar_kernel::config::Destinations {
            block_private_addresses:
                busbar_kernel::config::sections::DEFAULT_BLOCK_PRIVATE_ADDRESSES,
            ..Default::default()
        };
        busbar_core_connector::process::judge(
            busbar_core_connector::process::dest_judge(&config)
                .expect("production destination guard"),
            &[],
        )
    } else {
        Arc::new(judge)
    };
    Arc::new(Connector::serving(view, judge, Some(Arc::new(tls)), wake))
}

fn accept(listener: &TcpListener) -> TcpStream {
    listener.set_nonblocking(true).unwrap();
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                return stream;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < until,
                    "Vault never reached its declared need"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("accept Vault's request: {error}"),
        }
    }
}

fn request(stream: &mut impl Read) {
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).expect("the HTTP request head");
        head.push(byte[0]);
    }
    let head = String::from_utf8(head).unwrap();
    assert!(head.starts_with("GET /v1/kv/data/x HTTP/1.1\r\n"));
    assert!(head.lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("x-vault-token") && value.trim() == TOKEN
        })
    }));
}

fn response(status: u16, body: Vec<u8>, unfinished: bool) -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = format!("http://{}", listener.local_addr().unwrap());
    let served = std::thread::spawn(move || {
        let mut stream = accept(&listener);
        request(&mut stream);
        let declared = if unfinished {
            body.len() + (1024 * 1024)
        } else {
            body.len()
        };
        write!(
            stream,
            "HTTP/1.1 {status} Vault\r\nContent-Length: {declared}\r\n\r\n"
        )
        .unwrap();
        if let Err(error) = stream.write_all(&body) {
            assert!(
                unfinished
                    && matches!(
                        error.kind(),
                        std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
                    ),
                "writing the response: {error}"
            );
            return;
        }
        if unfinished {
            let mut byte = [0_u8; 1];
            match stream.read(&mut byte) {
                Ok(0) => {}
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
                other => panic!("the bounded exchange did not close its stream: {other:?}"),
            }
        }
    });
    (addr, served)
}

struct Lending {
    settings: Vec<u8>,
    material: Mutex<Vec<u8>>,
}

struct Answer {
    called: Called,
    kind: u32,
    needed: u64,
    material: Vec<u8>,
}

fn resolve(addr: &str, leg: Leg) -> Answer {
    resolve_waiting(addr, leg, None, RESOLVE_CAP)
}

fn resolve_waiting(
    addr: &str,
    leg: Leg,
    cancel: Option<std::sync::mpsc::Receiver<()>>,
    secret_cap: usize,
) -> Answer {
    resolve_with_timeout(addr, leg, cancel, secret_cap, 5)
}

fn resolve_with_timeout(
    addr: &str,
    leg: Leg,
    cancel: Option<std::sync::mpsc::Receiver<()>>,
    secret_cap: usize,
    timeout_secs: u64,
) -> Answer {
    let settings =
        serde_json::json!({"addr": addr, "token": TOKEN, "timeout_secs": timeout_secs}).to_string();
    let dispatcher = dispatcher();
    let plugin = plugin(&dispatcher, leg, "vault-bounded-response");
    let opened = open(&plugin, settings.as_bytes());
    assert_eq!(opened.outcome, Outcome::Ready, "{opened:?}");

    let answer = resolve_on(
        &plugin,
        &dispatcher,
        br#"{"path":"kv/data/x#k"}"#,
        cancel,
        secret_cap,
    );
    assert_eq!(close(&plugin).outcome, Outcome::Ready);
    answer
}

fn resolve_on(
    plugin: &Plugin<Secret>,
    dispatcher: &Dispatcher,
    reference: &[u8],
    cancel: Option<std::sync::mpsc::Receiver<()>>,
    secret_cap: usize,
) -> Answer {
    resolve_on_gated(plugin, dispatcher, reference, cancel, secret_cap, None)
}

fn resolve_on_gated(
    plugin: &Plugin<Secret>,
    dispatcher: &Dispatcher,
    reference: &[u8],
    cancel: Option<std::sync::mpsc::Receiver<()>>,
    secret_cap: usize,
    permit: Option<(
        &std::sync::mpsc::Sender<()>,
        &std::sync::atomic::AtomicUsize,
    )>,
) -> Answer {
    let entered = plugin.test_invocations().0;
    let resumed = plugin.test_invocations().1;
    let lending = Arc::new(Lending {
        settings: reference.to_vec(),
        material: Mutex::new(vec![0; secret_cap]),
    });
    let mut frame: Frame<ResolveIn, ResolveOut> = Frame::new(
        ResolveIn {
            head: in_head(),
            settings: NO_BLOB,
            secret_buf: std::ptr::null_mut(),
            secret_cap: 0,
        },
        ResolveOut {
            head: out_head(),
            secret: NO_BLOB,
            error_kind: 0,
            _reserved: 0,
            needed: 0,
        },
    );
    frame.input.settings = json(&lending.settings);
    {
        let mut material = lending.material.lock().unwrap();
        frame.input.secret_buf = material.as_mut_ptr();
        frame.input.secret_cap = material.len();
    }
    let deadline = busbar_plugin_loader::dispatch::now_ns() + 10_000_000_000;
    let cancelled = cancel.is_some();
    let (called, frame) = if let Some(cancel) = cancel {
        let ticket = dispatcher.mint(0).expect("a resolve ticket");
        let reply = dispatcher.submit_lent(
            plugin,
            ticket,
            secret::slot::RESOLVE,
            frame,
            DeadlineClass::Call,
            deadline,
            Arc::clone(&lending) as busbar_plugin_loader::dispatch::Lent,
        );
        cancel
            .recv_timeout(Duration::from_secs(10))
            .expect("the server sent a partial response before cancellation");
        dispatcher.drop_client(ticket);
        let done = reply.wait_done();
        dispatcher.recycle(ticket);
        assert!(
            dispatcher.retirement_barrier(ticket, Duration::from_secs(10)),
            "the cancelled resolve retires before another lifecycle call"
        );
        assert_eq!(done.disposition, Some(secret::cancel::ABORTED));
        (
            Called {
                outcome: done.outcome,
                error: done.error,
                lease: done.lease,
                recall: None,
            },
            done.frame,
        )
    } else {
        let ticket = dispatcher.mint(0).expect("a resolve ticket");
        let reply = dispatcher.submit_lent(
            plugin,
            ticket,
            secret::slot::RESOLVE,
            frame,
            DeadlineClass::Call,
            deadline,
            Arc::clone(&lending) as busbar_plugin_loader::dispatch::Lent,
        );
        if let Some((permit, observed)) = permit {
            let until = Instant::now() + Duration::from_secs(10);
            while plugin.test_invocations().1 == resumed {
                if let Some(done) = reply.wait(Duration::ZERO) {
                    if let Some(error) = &done.error {
                        clean(error);
                    }
                    panic!("gated resolve ended before response release: outcome {:?}, sanitized error {:?}, prior completed actual HTTP requests {}",done.outcome,done.error.as_deref().map(String::from_utf8_lossy),observed.load(std::sync::atomic::Ordering::SeqCst));
                }
                assert!(
                    Instant::now() < until,
                    "actual worker resumes on response prefix before the final body is released"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
            permit.send(()).unwrap();
        }
        let done = reply.wait_done();
        dispatcher.recycle(ticket);
        // Reply delivery precedes the worker's deferred binding-admission drop. REFRESH
        // correctly refuses while that crossing is still retiring, so synchronize with
        // retirement rather than racing it or retrying away the crossing assertion.
        assert!(
            dispatcher.retirement_barrier(ticket, Duration::from_secs(10)),
            "the completed resolve retires before another lifecycle call"
        );
        (
            Called {
                outcome: done.outcome,
                error: done.error,
                lease: done.lease,
                recall: None,
            },
            done.frame,
        )
    };
    let resumes = plugin.test_invocations().1 - resumed;
    let first_entries = plugin.test_invocations().0 - entered - resumes;
    let host_refusal = matches!(called.outcome, Outcome::Refused | Outcome::Fault);
    if cancelled {
        assert!(
            first_entries >= 1,
            "the cancelled actual resolve entered its door"
        );
    } else {
        assert_eq!(
            first_entries,
            u64::from(!host_refusal),
            "exact actual Vault first entries"
        );
    }
    if let Some(error) = &called.error {
        clean(error);
    }
    let frame = frame.expect("the resolve returned its frame");
    assert_eq!(called.lease, 0, "a secret resolve never lends a lease");
    if let Some(error) = &called.error {
        assert!(
            !error
                .windows(TOKEN.len())
                .any(|bytes| bytes == TOKEN.as_bytes()),
            "a refusal must not disclose the Vault token"
        );
        assert!(
            !error.windows(MATERIAL.len()).any(|bytes| bytes == MATERIAL),
            "a refusal must not disclose the response material"
        );
    }
    let material = {
        let material = lending.material.lock().unwrap();
        if called.outcome == Outcome::Ready {
            assert_eq!(frame.out.secret.fmt, BLOB_OCTETS);
            assert_ne!(frame.out.secret.flags & BLOB_SECRET, 0);
            assert_eq!(frame.out.secret.ptr, material.as_ptr());
            assert!(frame.out.secret.len > 0);
            assert!(frame.out.secret.len <= material.len());
            material[..frame.out.secret.len].to_vec()
        } else {
            assert_eq!(frame.out.secret.flags & BLOB_SECRET, 0);
            assert!(frame.out.secret.ptr.is_null());
            assert_eq!(frame.out.secret.len, 0);
            assert!(
                material.iter().all(|byte| *byte == 0),
                "a refused resolve must leave its lent secret buffer untouched"
            );
            Vec::new()
        }
    };
    let kind = frame.out.error_kind;
    let needed = frame.out.needed;
    assert_eq!(
        dispatcher.stats().deadline_without_wake,
        0,
        "every pending exchange completed through its wakes"
    );
    Answer {
        called,
        kind,
        needed,
        material,
    }
}

#[test]
fn a_real_short_answer_names_the_needed_length_without_writing_partial_material() {
    const BODY: &[u8] = br#"{"data":{"data":{"k":"bounded-material"}}}"#;
    for leg in [Leg::Linked, Leg::Dropped] {
        let (addr, served) = response(HTTP_OK, BODY.to_vec(), false);
        let answer = resolve_waiting(&addr, leg, None, MATERIAL.len() - 1);
        served.join().unwrap_or_else(|_| {
            panic!(
                "actual response server failed; sanitized product answer {:?}",
                answer.called
            )
        });
        assert_eq!(
            answer.called.outcome,
            Outcome::Failed,
            "{:?}",
            answer.called
        );
        assert_eq!(answer.kind, secret::ERROR_KIND_UNSET);
        assert_eq!(answer.needed, MATERIAL.len() as u64);
        assert!(answer
            .called
            .error
            .as_deref()
            .unwrap_or_default()
            .is_empty());
        assert!(answer.material.is_empty());
    }
}

#[test]
fn the_real_exchange_accepts_at_the_cap_and_refuses_one_byte_past_it() {
    let cap = 1024 * 1024;
    for leg in [Leg::Linked, Leg::Dropped] {
        for len in [cap, cap + 1] {
            let mut body = br#"{"data":{"data":{"k":"bounded-material"}}}"#.to_vec();
            body.resize(len, b' ');
            let (addr, served) = response(200, body, false);
            let answer = resolve(&addr, leg);
            served.join().unwrap();
            if len == cap {
                assert_eq!(answer.called.outcome, Outcome::Ready, "{:?}", answer.called);
                assert_eq!(answer.material, MATERIAL);
            } else {
                assert_eq!(
                    answer.called.outcome,
                    Outcome::Failed,
                    "{:?}",
                    answer.called
                );
                let text = String::from_utf8(answer.called.error.unwrap()).unwrap();
                assert!(
                    text.starts_with("Vault response body exceeds the "),
                    "{text}"
                );
            }
        }
    }
}

#[test]
fn an_unfinished_reply_past_the_cap_preserves_the_actual_status_and_closes() {
    let cap = 1024 * 1024;
    for leg in [Leg::Linked, Leg::Dropped] {
        for status in [200, 400, 403, 404, 503] {
            let body = vec![b'x'; cap + 16 * 1024];
            let (addr, served) = response(status, body, true);
            let answer = resolve(&addr, leg);
            served.join().unwrap_or_else(|_| {
                panic!(
                    "actual response server failed; sanitized product answer {:?}",
                    answer.called
                )
            });
            use busbar_contract::secret::SecretModuleError;
            let url = format!("{addr}/v1/kv/data/x");
            let expected = match status {
                404 => SecretModuleError::not_found(format!("Vault has no secret at path \"kv/data/x\" (404 from {url})")),
                403 => SecretModuleError::denied(format!("Vault denied reading path \"kv/data/x\" (403 Forbidden from {url}): check the token is valid and its policy grants read on this path")),
                503 => SecretModuleError::unavailable(format!("Vault server error reading path \"kv/data/x\": HTTP 503 Service Unavailable from {url}")),
                _ => SecretModuleError::unavailable(format!("Vault response body exceeds the {cap}-byte cap (path \"kv/data/x\", {url})")),
            };
            assert_eq!(
                answer.called.outcome,
                Outcome::Failed,
                "{:?}",
                answer.called
            );
            assert_eq!(
                answer.kind,
                busbar_contract::abi::sdk::secret::error_kind(expected.kind)
            );
            assert_eq!(answer.called.error.unwrap(), expected.message.as_bytes());
        }
    }
}

#[test]
fn a_real_redirect_does_not_send_the_vault_token_to_its_location() {
    for leg in [Leg::Linked, Leg::Dropped] {
        let destination = TcpListener::bind("127.0.0.1:0").unwrap();
        destination.set_nonblocking(true).unwrap();
        let location = format!("http://{}/stolen", destination.local_addr().unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = format!("http://{}", listener.local_addr().unwrap());
        let served = std::thread::spawn(move || {
            let mut stream = accept(&listener);
            request(&mut stream);
            write!(
                stream,
                "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\n\r\n"
            )
            .unwrap();
        });
        let answer = resolve(&addr, leg);
        served.join().unwrap_or_else(|_| {
            panic!(
                "actual response server failed; sanitized product answer {:?}",
                answer.called
            )
        });
        assert_eq!(
            answer.called.outcome,
            Outcome::Failed,
            "{:?}",
            answer.called
        );
        let text = String::from_utf8(answer.called.error.unwrap()).unwrap();
        assert!(text.contains("a redirect is not followed"), "{text}");
        match destination.accept() {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            other => panic!("the redirect destination was contacted: {other:?}"),
        }
    }
}

#[test]
fn a_ca_that_is_not_a_trust_anchor_refuses_the_actual_open_before_any_request() {
    let ca = "-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----";
    for leg in [Leg::Linked, Leg::Dropped] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let settings = serde_json::json!({
            "addr": format!("https://{}", listener.local_addr().unwrap()),
            "token": TOKEN, "ca_cert_pem": ca,
        })
        .to_string();
        let dispatcher = dispatcher();
        let plugin = plugin(&dispatcher, leg, "vault-rejected-ca");
        assert_eq!(
            validate(&plugin, settings.as_bytes()).outcome,
            Outcome::Ready
        );
        let opened = open(&plugin, settings.as_bytes());
        assert_eq!(opened.outcome, Outcome::Failed, "{opened:?}");
        let text = String::from_utf8(opened.error.unwrap()).unwrap();
        assert!(
            text.contains("the host refused the CA certificate"),
            "{text}"
        );
        assert!(!text.contains(TOKEN));
        assert!(!text.contains(ca));
        match listener.accept() {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            other => panic!("a refused operator CA reached the network: {other:?}"),
        }
        assert_eq!(
            dispatcher.stats().deadline_without_wake,
            0,
            "refusing admission issued no waiting operation"
        );
    }
}

#[test]
fn escaped_material_and_malformed_nested_replies_keep_the_host_buffer_in_custody() {
    for leg in [Leg::Linked, Leg::Dropped] {
        for (body, ready) in [
            (
                br#"{"data":{"data":{"\u006b":"bounded\u002dmaterial"}}}"#.as_slice(),
                true,
            ),
            (
                br#"{"data":{"data":{"k":"bounded\u002dmaterial","other":["partial",]}}}"#,
                false,
            ),
            (
                br#"{"data":{"data":{"k":"bounded\u002dmaterial\q"}}}"#,
                false,
            ),
        ] {
            let (addr, served) = response(200, body.to_vec(), false);
            let answer = resolve(&addr, leg);
            served.join().unwrap_or_else(|_| {
                panic!(
                    "actual response server failed; sanitized product answer {:?}",
                    answer.called
                )
            });
            if ready {
                assert_eq!(answer.called.outcome, Outcome::Ready);
                assert_eq!(answer.material, MATERIAL);
            } else {
                assert_eq!(answer.called.outcome, Outcome::Failed);
                assert_eq!(answer.kind, secret::ERROR_KIND_INTERNAL);
                let error = String::from_utf8(answer.called.error.unwrap()).unwrap();
                assert!(error.contains("is not valid JSON"));
                assert!(!error.contains("bounded"));
            }
        }
    }
}

#[test]
fn cancelling_a_partial_escaped_reply_leaves_the_initialized_host_buffer_untouched() {
    for leg in [Leg::Linked, Leg::Dropped] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = format!("http://{}", listener.local_addr().unwrap());
        let (sent, received) = std::sync::mpsc::channel();
        let served = std::thread::spawn(move || {
            let mut stream = accept(&listener);
            request(&mut stream);
            let partial = br#"{"data":{"data":{"k":"bounded\u002dmaterial"#;
            write!(
                stream,
                "HTTP/1.1 200 Vault\r\nContent-Length: {}\r\n\r\n",
                partial.len() + 4
            )
            .unwrap();
            stream.write_all(partial).unwrap();
            sent.send(()).unwrap();
            let mut byte = [0_u8; 1];
            match stream.read(&mut byte) {
                Ok(0) => {}
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
                other => panic!("cancellation did not close the pending exchange: {other:?}"),
            }
        });
        let answer = resolve_waiting(&addr, leg, Some(received), RESOLVE_CAP);
        served.join().unwrap();
        assert_eq!(answer.called.outcome, Outcome::Failed);
        assert!(answer.material.is_empty());
    }
}

#[test]
fn the_configured_total_timeout_closes_a_silent_tls_establishment() {
    for leg in [Leg::Linked, Leg::Dropped] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = format!("https://{}", listener.local_addr().unwrap());
        let served = std::thread::spawn(move || {
            let mut stream = accept(&listener);

            let mut hello = [0_u8; 16 * 1024];
            assert!(stream.read(&mut hello).unwrap() > 0);
            let waiting_since = Instant::now();
            stream
                .set_read_timeout(Some(Duration::from_secs(6)))
                .unwrap();
            loop {
                match stream.read(&mut hello) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => break,
                    other => panic!(
                        "the configured timeout did not close its pending TLS stream: {other:?}"
                    ),
                }
            }
            waiting_since
        });
        let answer = resolve_with_timeout(&addr, leg, None, RESOLVE_CAP, 1);
        let completed = Instant::now();
        let elapsed = completed.saturating_duration_since(served.join().unwrap_or_else(|_| {
            panic!(
                "actual response server failed; sanitized product answer {:?}",
                answer.called
            )
        }));
        assert_eq!(
            answer.called.outcome,
            Outcome::Failed,
            "{:?}",
            answer.called
        );
        assert_eq!(answer.kind, secret::ERROR_KIND_UNAVAILABLE);
        assert!(
            elapsed < Duration::from_secs(4),
            "configured 1s bound waited {elapsed:?}"
        );
        assert!(answer.material.is_empty());
    }
}

#[test]
fn the_configured_total_timeout_collects_no_partial_secret_after_a_response_head() {
    for leg in [Leg::Linked, Leg::Dropped] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = format!("http://{}", listener.local_addr().unwrap());
        let served = std::thread::spawn(move || {
            let mut stream = accept(&listener);
            request(&mut stream);
            let partial = br#"{"data":{"data":{"k":"bounded\u002dmaterial"#;
            write!(
                stream,
                "HTTP/1.1 200 Vault\r\nContent-Length: {}\r\n\r\n",
                partial.len() + 4
            )
            .unwrap();
            stream.write_all(partial).unwrap();
            let waiting_since = Instant::now();
            stream
                .set_read_timeout(Some(Duration::from_secs(6)))
                .unwrap();
            let mut byte = [0_u8; 1];
            match stream.read(&mut byte) {
                Ok(0) => {}
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
                other => {
                    panic!("the configured timeout did not close its incomplete body: {other:?}")
                }
            }
            waiting_since
        });
        let answer = resolve_with_timeout(&addr, leg, None, RESOLVE_CAP, 1);
        let completed = Instant::now();
        let elapsed = completed.saturating_duration_since(served.join().unwrap_or_else(|_| {
            panic!(
                "actual response server failed; sanitized product answer {:?}",
                answer.called
            )
        }));
        assert_eq!(
            answer.called.outcome,
            Outcome::Failed,
            "{:?}",
            answer.called
        );
        assert_eq!(answer.kind, secret::ERROR_KIND_UNAVAILABLE);
        assert!(
            elapsed < Duration::from_secs(4),
            "configured 1s bound waited {elapsed:?}"
        );
        assert!(answer.material.is_empty());
    }
}

#[test]
fn a_huge_configured_timeout_uses_the_outer_call_cap_without_overflow_refusal() {
    const BODY: &[u8] = br#"{"data":{"data":{"k":"bounded-material"}}}"#;
    for leg in [Leg::Linked, Leg::Dropped] {
        let (addr, served) = response(HTTP_OK, BODY.to_vec(), false);
        let answer = resolve_with_timeout(&addr, leg, None, RESOLVE_CAP, u64::MAX);
        served.join().unwrap_or_else(|_| {
            panic!(
                "actual response server failed; sanitized product answer {:?}",
                answer.called
            )
        });
        assert_eq!(answer.called.outcome, Outcome::Ready, "{:?}", answer.called);
        assert_eq!(answer.material, MATERIAL);
    }
}

// A real TLS endpoint with a fresh CA and localhost leaf. It implements only the far end's
// HTTP response; all client transport, trust admission and framing belong to the real connector.
fn tls_response() -> (String, String, JoinHandle<bool>) {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
    let ca_key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::from_params(&params, ca_key);
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec!["localhost".to_owned()])
        .unwrap()
        .signed_by(&leaf_key, &issuer)
        .unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![leaf.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(leaf_key.serialize_der()).into(),
    )
    .unwrap();
    let listener = TcpListener::bind(("localhost", 0)).unwrap();
    let addr = format!(
        "https://localhost:{}",
        listener.local_addr().unwrap().port()
    );
    let served = std::thread::spawn(move || {
        let mut tcp = accept(&listener);
        let mut connection = rustls::ServerConnection::new(Arc::new(config)).unwrap();
        while connection.is_handshaking() {
            if connection.complete_io(&mut tcp).is_err() {
                return false;
            }
        }
        let mut stream = rustls::StreamOwned::new(connection, tcp);
        request(&mut stream);
        let body = br#"{"data":{"data":{"k":"bounded-material"}}}"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n",
            body.len()
        )
        .unwrap();
        stream.write_all(body).unwrap();
        stream.flush().unwrap();
        stream.conn.send_close_notify();
        let _ = stream.conn.complete_io(&mut stream.sock);
        true
    });
    (addr, ca.pem(), served)
}

#[test]
fn the_actual_vault_http_need_verifies_a_local_tls_leaf_and_refuses_withheld_anchors() {
    for leg in [Leg::Linked, Leg::Dropped] {
        for trusted in [true, false] {
            let (addr, ca, served) = tls_response();
            let d = dispatcher();
            let p = plugin_with_trust(&d, leg, "vault-local-tls", trusted.then_some(ca.as_str()));
            let settings =
                serde_json::json!({"addr": addr, "token": TOKEN, "timeout_secs": 5}).to_string();
            assert_eq!(open(&p, settings.as_bytes()).outcome, Outcome::Ready);
            let answer = resolve_on(&p, &d, br#"{"path":"kv/data/x#k"}"#, None, RESOLVE_CAP);
            assert_eq!(
                served.join().unwrap(),
                trusted,
                "only the admitted TLS peer sees the HTTP request"
            );
            if trusted {
                assert_eq!(answer.called.outcome, Outcome::Ready);
                assert_eq!(answer.material, MATERIAL);
            } else {
                assert_eq!(answer.called.outcome, Outcome::Failed);
                assert!(answer.material.is_empty());
            }
            assert_eq!(close(&p).outcome, Outcome::Ready);
        }
    }
}

#[test]
fn the_production_guard_refuses_private_and_metadata_dials_and_admits_operator_loopback() {
    use busbar_contract::abi::host::conn::connector::{
        DIRECTION_OUTBOUND, EGRESS_DEFAULT, EGRESS_OPERATOR_INFRASTRUCTURE, KEEP_NAMED,
    };
    use busbar_contract::abi::mechanism::rendering::{ReadBlob, ReadNeed};
    use busbar_contract::conn::{ConnError, InstanceId, NeedId, OpenDesc};
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let table = host(Arc::new(|_, _| {}), None, true);
    let owner = InstanceId(7);
    let mut sequence = 0;
    let mut dial = |class, target: &str| {
        sequence += 1;
        let need_id = NeedId(sequence);
        table
            .declare(
                owner,
                need_id,
                &ReadNeed {
                    direction: DIRECTION_OUTBOUND,
                    egress_class: class,
                    transport: "tcp".to_owned(),
                    auth: String::new(),
                    target_from: String::new(),
                    trust_from: String::new(),
                    details: ReadBlob {
                        fmt: 0,
                        flags: 0,
                        bytes: Vec::new(),
                    },
                    timeout_ms: 0,
                    keep_mode: KEEP_NAMED,
                    keep_response_headers: Vec::new(),
                    deny_response_headers: Vec::new(),
                },
                None,
                None,
            )
            .unwrap();
        let until = Instant::now() + Duration::from_secs(10);
        loop {
            let answer = table.open(
                owner,
                need_id,
                &OpenDesc {
                    target,
                    timeout_ms: 2000,
                    ..Default::default()
                },
            );
            match answer {
                Err(ConnError::Pending) => {
                    assert!(Instant::now() < until);
                    std::thread::sleep(Duration::from_millis(2));
                }
                answer => break answer,
            }
        }
    };
    for (class, target) in [
        (EGRESS_DEFAULT, "10.0.0.1:443"),
        (EGRESS_DEFAULT, address.as_str()),
        (EGRESS_OPERATOR_INFRASTRUCTURE, "169.254.169.254:80"),
    ] {
        assert_eq!(dial(class, target).map(|_| ()), Err(ConnError::Refused));
    }
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
        "no refused destination is dialled"
    );
    let id =
        dial(EGRESS_OPERATOR_INFRASTRUCTURE, &address).expect("operator loopback control admitted");
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        match listener.accept() {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < until,
                    "admitted dial reached its actual listener"
                );
                std::thread::sleep(Duration::from_millis(2));
            }
            other => panic!("loopback listener: {other:?}"),
        }
    }
    table
        .close(owner, id)
        .expect("close actual control connection");
}

#[test]
fn selected_null_refuses_without_material_while_string_null_resolves_through_both_doors() {
    for leg in [Leg::Linked, Leg::Dropped] {
        for (body, expected) in [
            (
                br#"{"data":{"data":{"k":null}}}"#.as_slice(),
                Outcome::Failed,
            ),
            (
                br#"{"data":{"data":{"k":"null"}}}"#.as_slice(),
                Outcome::Ready,
            ),
        ] {
            let (addr, served) = response(200, body.to_vec(), false);
            let answer = resolve(&addr, leg);
            served.join().unwrap();
            assert_eq!(answer.called.outcome, expected);
            if expected == Outcome::Failed {
                assert_eq!(answer.kind, secret::ERROR_KIND_INVALID);
                assert!(answer.material.is_empty());
                assert_eq!(answer.needed, 0);
            } else {
                assert_eq!(answer.material, b"null");
            }
        }
    }
}

#[test]
fn ordinary_lifecycle_resolution_and_refused_refresh_preserve_the_vault_contract() {
    use busbar_contract::abi::mechanism::lifecycle::{RefreshIn, ReleaseIn, TickIn, TickOut};
    use busbar_contract::abi::secret::CheckIn;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
    struct Server {
        stop: Arc<AtomicBool>,
        task: Option<JoinHandle<()>>,
        calls: Arc<AtomicUsize>,
        addr: String,
        permit: std::sync::mpsc::Sender<()>,
    }
    impl Drop for Server {
        fn drop(&mut self) {
            self.stop.store(true, SeqCst);
            if let Some(task) = self.task.take() {
                if let Err(failure) = task.join() {
                    if !std::thread::panicking() {
                        std::panic::resume_unwind(failure);
                    }
                }
            }
        }
    }
    impl Server {
        fn finish(mut self) -> usize {
            self.stop.store(true, SeqCst);
            self.task.take().unwrap().join().unwrap();
            self.calls.load(SeqCst)
        }
    }
    fn closed_resolve(p: &Plugin<Secret>) {
        let before = p.test_invocations().0;
        let mut bytes = [0u8; 32];
        let mut frame = Frame::new(
            ResolveIn {
                head: in_head(),
                settings: json(br#"{"path":"kv/data/x#k"}"#),
                secret_buf: bytes.as_mut_ptr(),
                secret_cap: bytes.len(),
            },
            ResolveOut {
                head: out_head(),
                secret: NO_BLOB,
                error_kind: 0,
                _reserved: 0,
                needed: 0,
            },
        );
        let called = p.call(secret::slot::RESOLVE, &mut frame);
        assert_ne!(called.outcome, Outcome::Ready);
        assert_eq!(called.lease, 0);
        assert_eq!(
            p.test_invocations().0,
            before,
            "host refuses a non-open instance before entering product"
        );
        assert!(frame.out.secret.ptr.is_null());
        assert_eq!(frame.out.secret.len, 0);
        assert_eq!(bytes, [0; 32]);
    }
    fn server() -> Server {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let calls = Arc::new(AtomicUsize::new(0));
        let stopped = Arc::clone(&stop);
        let observed = Arc::clone(&calls);
        let (permit, permits) = std::sync::mpsc::channel();
        let task = std::thread::spawn(move || {
            while !stopped.load(SeqCst) {
                let (mut stream, _) = match listener.accept() {
                    Ok(accepted) => accepted,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    Err(error) => panic!("Vault endpoint accept: {error}"),
                };
                // Accepted sockets can inherit O_NONBLOCK on macOS; use blocking I/O here.
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    stream.read_exact(&mut byte).unwrap();
                    head.push(byte[0]);
                }
                let head = String::from_utf8(head).unwrap();
                assert!(head.lines().any(|line| line
                    .split_once(':')
                    .is_some_and(|(name, value)| name.eq_ignore_ascii_case("x-vault-token")
                        && value.trim() == TOKEN)));
                let missing = head.lines().next().unwrap().contains("/absent ");
                assert!(missing || head.starts_with("GET /v1/kv/data/x HTTP/1.1\r\n"));
                let status = if missing { 404 } else { 200 };
                let body = if missing {
                    "{\"errors\":[]}".to_string()
                } else {
                    serde_json::json!({"data":{"data":{"k":std::str::from_utf8(MATERIAL).unwrap()}}}).to_string()
                };
                write!(
                    stream,
                    "HTTP/1.1 {status} Vault\r\nTransfer-Encoding: chunked\r\n\r\n"
                )
                .unwrap();
                stream.flush().unwrap();
                let until = Instant::now() + Duration::from_secs(10);
                loop {
                    match permits.try_recv() {
                        Ok(()) => break,
                        Err(std::sync::mpsc::TryRecvError::Disconnected) => return,
                        Err(std::sync::mpsc::TryRecvError::Empty) => {
                            if stopped.load(SeqCst) {
                                return;
                            }
                            assert!(
                                Instant::now() < until,
                                "actual response-prefix wake resumes the worker"
                            );
                            stream.write_all(b"1\r\n \r\n").unwrap();
                            stream.flush().unwrap();
                            std::thread::sleep(Duration::from_millis(1));
                        }
                    }
                }
                write!(stream, "{:X}\r\n{body}\r\n0\r\n\r\n", body.len()).unwrap();
                stream.flush().unwrap();
                observed.fetch_add(1, SeqCst);
            }
        });
        Server {
            stop,
            task: Some(task),
            calls,
            addr,
            permit,
        }
    }
    fn controlled_resolve(
        p: &Plugin<Secret>,
        d: &Dispatcher,
        reference: &[u8],
        cap: usize,
        permit: &std::sync::mpsc::Sender<()>,
        observed: &AtomicUsize,
    ) -> Answer {
        let resumed = p.test_invocations().1;
        let answer = resolve_on_gated(p, d, reference, None, cap, Some((permit, observed)));
        assert!(
            p.test_invocations().1 > resumed,
            "withheld actual HTTP response forces actual worker PENDING and RESUME"
        );
        answer
    }
    for leg in [Leg::Linked, Leg::Dropped] {
        let server = server();
        let d = dispatcher();
        let p = plugin(&d, leg, "vault-ordinary-lifecycle");
        let statement = busbar_contract::abi::mechanism::rendering::read(
            &busbar_plugin_loader::dispatch::rendering_of(busbar_secret_vault::door).unwrap(),
        )
        .unwrap();
        let mut needs: Vec<_> = statement
            .needs
            .iter()
            .map(|need| need.transport.as_str())
            .filter(|name| !name.is_empty())
            .collect();
        needs.sort();
        needs.dedup();
        assert_eq!(needs, ["http"]);
        let declarations: serde_json::Value =
            serde_json::from_str(include_str!("../../secret-vault/declares.json")).unwrap();
        assert_eq!(declarations["needs"], serde_json::json!(["http"]));
        assert!(!(cfg!(debug_assertions) && std::env::var_os("BUSBAR_EXPECT_RELEASE").is_some()));
        let settings =
            serde_json::json!({"addr":server.addr,"token":TOKEN,"timeout_secs":5}).to_string();
        let bad_settings = [
            "".to_string(),
            serde_json::json!({"token":"s.x"}).to_string(),
            serde_json::json!({"addr":server.addr,"token":"s.x","bogus":1}).to_string(),
            serde_json::json!({"addr":"localhost:58940","token":"s.x"}).to_string(),
            serde_json::json!({"addr":server.addr,"token":"s.x","timeout_secs":0}).to_string(),
            serde_json::json!({"addr":server.addr,"token":"s.x","ca_cert_pem":"not a pem"})
                .to_string(),
        ];
        for bad in &bad_settings {
            let validation = validate(&p, bad.as_bytes());
            assert_eq!(validation.outcome, Outcome::Failed);
            assert_eq!(validation.lease, 0);
            assert!(!validation.error.as_deref().unwrap_or_default().is_empty());
            let opening = open(&p, bad.as_bytes());
            assert_eq!(opening.outcome, Outcome::Failed);
            assert_eq!(opening.lease, 0);
        }
        closed_resolve(&p);
        let entries = p.test_invocations().0;
        p.ready(&d, Duration::from_secs(10)).unwrap();
        assert_eq!(p.test_invocations().0 - entries, u64::from(p.has_ready()));
        assert_eq!(open(&p, settings.as_bytes()).outcome, Outcome::Ready);
        assert_ne!(open(&p, settings.as_bytes()).outcome, Outcome::Ready);
        for reference in [
            br#"{"path":"kv/data/x#k"}"#.as_slice(),
            br#"{"path":"kv/data/x"}"#,
            br#"{"name":5}"#,
        ] {
            let before = server.calls.load(SeqCst);
            let mut reason = [0u8; 1024];
            let mut f: Frame<CheckIn, OutHead> = Frame::new(
                CheckIn {
                    head: in_head(),
                    settings: json(reference),
                    err_buf: reason.as_mut_ptr(),
                    err_cap: reason.len(),
                },
                out_head(),
            );
            let answer = checked_call(&p, secret::slot::CHECK, &mut f);
            assert_eq!(answer.outcome,Outcome::Ready,"Vault uses the SDK default pure object CHECK; reference grammar is judged at RESOLVE");
            assert_eq!(answer.lease, 0);
            assert_eq!(
                server.calls.load(SeqCst),
                before,
                "reference CHECK performs no network IO"
            );
        }
        for _ in 0..2 {
            let answer = controlled_resolve(
                &p,
                &d,
                br#"{"path":"kv/data/x#k"}"#,
                RESOLVE_CAP,
                &server.permit,
                &server.calls,
            );
            assert_eq!(
                answer.called.outcome,
                Outcome::Ready,
                "sanitized answer {:?}, prior actual wire calls {}",
                answer.called,
                server.calls.load(SeqCst)
            );
            assert_eq!(answer.material, MATERIAL);
        }
        let missing = controlled_resolve(
            &p,
            &d,
            br#"{"path":"kv/data/absent#k"}"#,
            RESOLVE_CAP,
            &server.permit,
            &server.calls,
        );
        assert_eq!(missing.called.outcome, Outcome::Failed);
        assert_eq!(missing.kind, secret::ERROR_KIND_NOT_FOUND);
        for reference in [br#"{"path":"kv/data/x"}"#.as_slice(), br#"{"name":5}"#] {
            let malformed = resolve_on(&p, &d, reference, None, RESOLVE_CAP);
            assert_eq!(malformed.called.outcome, Outcome::Failed);
            assert_eq!(malformed.kind, secret::ERROR_KIND_INVALID);
        }
        let short = controlled_resolve(
            &p,
            &d,
            br#"{"path":"kv/data/x#k"}"#,
            MATERIAL.len() - 1,
            &server.permit,
            &server.calls,
        );
        assert_eq!(short.called.outcome, Outcome::Failed);
        assert_eq!(short.needed, MATERIAL.len() as u64);
        assert!(short.material.is_empty());
        let recalled = controlled_resolve(
            &p,
            &d,
            br#"{"path":"kv/data/x#k"}"#,
            short.needed as usize,
            &server.permit,
            &server.calls,
        );
        assert_eq!(recalled.called.outcome, Outcome::Ready);
        assert_eq!(recalled.material, MATERIAL);
        let token = Blob {
            ptr: TOKEN.as_ptr(),
            len: TOKEN.len(),
            fmt: BLOB_OCTETS,
            flags: BLOB_SECRET,
        };
        for (refresh_index, refresh_settings) in bad_settings
            .iter()
            .map(String::as_str)
            .chain(std::iter::once(settings.as_str()))
            .enumerate()
        {
            if refresh_index > 0 && refresh_index < bad_settings.len() {
                let mut reset: Frame<RefreshIn, OutHead> = Frame::new(
                    RefreshIn {
                        head: in_head(),
                        generation: 2,
                        settings: json(settings.as_bytes()),
                        secrets: &token,
                        secrets_len: 1,
                    },
                    out_head(),
                );
                assert_eq!(
                    checked_call(&p, life::slot::REFRESH, &mut reset).outcome,
                    Outcome::Ready
                );
            }
            let mut f: Frame<RefreshIn, OutHead> = Frame::new(
                RefreshIn {
                    head: in_head(),
                    generation: 2,
                    settings: json(refresh_settings.as_bytes()),
                    secrets: &token,
                    secrets_len: 1,
                },
                out_head(),
            );
            let answer = checked_call(&p, life::slot::REFRESH, &mut f);
            assert_eq!(
                answer.outcome,
                if refresh_settings != settings {
                    Outcome::Failed
                } else {
                    Outcome::Ready
                }
            );
            let still_serving = controlled_resolve(
                &p,
                &d,
                br#"{"path":"kv/data/x#k"}"#,
                RESOLVE_CAP,
                &server.permit,
                &server.calls,
            );
            assert_eq!(still_serving.called.outcome, Outcome::Ready);
            assert_eq!(still_serving.material, MATERIAL);
        }
        let mut release: Frame<ReleaseIn, OutHead> = Frame::new(
            ReleaseIn {
                head: in_head(),
                lease: 42,
            },
            out_head(),
        );
        assert_eq!(
            checked_call(&p, life::slot::RELEASE, &mut release).outcome,
            Outcome::Refused
        );
        let mut tick = Frame::new(
            TickIn {
                head: in_head(),
                now_ns: 1,
            },
            TickOut {
                head: out_head(),
                next_tick_ns: 7,
            },
        );
        assert_eq!(
            checked_call(&p, life::slot::TICK, &mut tick).outcome,
            Outcome::Ready
        );
        assert_eq!(tick.out.next_tick_ns, 0);
        assert_eq!(close(&p).outcome, Outcome::Ready);
        closed_resolve(&p);
        assert_eq!(server.finish(), 5 + bad_settings.len() + 1);
    }
}
