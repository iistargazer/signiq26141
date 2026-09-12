//! SIH26141 — Quantum-Secured Pipeline API server.
//!
//! REST + SSE facade over the quantum / detection / crypto crates:
//!   GET  /api/health   — liveness probe
//!   POST /api/run      — full simulation (secure + attack scenarios) with live SSE progress
//!   POST /api/simulate — parameter sweep over intercept ratios
//!   GET  /api/events   — SSE stream of live run events
//!   /api/qds/*         — teleportation-based QDS signature lab (see qds_api.rs)
//!   GET  /             — serves the built frontend from ../frontend/dist

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::routing::{get, post};
use axum::{Json, Router};
use qds_api::{qds_router, QdsStateHolder};
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use tower_http::cors::CorsLayer;

use crypto::{compute_message_hmac, verify_message_hmac};
use detection::ThreatDetector;
use quantum::{privacy_amplification, ChannelSession, QuantumKeyGenerator, SiftedKeyResult};

mod qds_api;
mod qds_state;

const DEFAULT_PORT: u16 = 8080;
const DEFAULT_KEY_LENGTH: usize = 3000;
const MIN_KEY_LENGTH: usize = 500;
const MAX_KEY_LENGTH: usize = 200_000;
const DEFAULT_BASE_THRESHOLD: f64 = 0.15;
const DEFAULT_PACE_MS: u64 = 4;
const MAX_MESSAGE_LEN: usize = 10_000;

/// Live events broadcast on the SSE stream while a run executes.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum RunEvent {
    /// Emitted after every batch of processed qubits.
    Progress {
        run_id: u64,
        scenario: String,
        processed: usize,
        total: usize,
        sifted: usize,
        mismatches: usize,
        qber: f64,
        /// Hoeffding-adjusted detection threshold at this sample size.
        threshold: f64,
    },
    /// Final verdict for one scenario.
    Result { run_id: u64, result: ScenarioResult },
    /// Emitted when the whole run is done.
    Done { run_id: u64 },
}

struct AppState {
    events_tx: broadcast::Sender<Arc<RunEvent>>,
    /// Last completed run per run_id, so late SSE subscribers can catch up.
    last_result: Mutex<Option<RunResponse>>,
    run_counter: AtomicU64,
    /// QDS signature-lab state (Trent + event log + last signature).
    qds: Mutex<QdsStateHolder>,
    /// Path of the persistent QDS security-event log (JSONL).
    qds_log_path: PathBuf,
    /// The port the server actually bound (differs from the request only
    /// after a port-fallback; the frontend discovers it via /api/server-info
    /// and frontend/dist/server-port.json). Atomic because the listener is
    /// bound after state construction.
    bound_port: std::sync::atomic::AtomicU16,
}

#[derive(Debug, Deserialize)]
struct RunRequest {
    key_length: Option<usize>,
    base_threshold: Option<f64>,
    /// Fraction of qubits Eve intercepts (0.0–1.0). None = two canonical
    /// scenarios (clean + full attack); Some(r) = one scenario at ratio r.
    intercept_ratio: Option<f64>,
    /// Message to authenticate with the derived key.
    message: Option<String>,
    /// Seed for reproducible runs.
    seed: Option<u64>,
    /// Per-batch pacing delay in ms so the live monitor is watchable. 0 = fast.
    pace_ms: Option<u64>,
}

#[derive(Debug, Serialize, Clone)]
struct ScenarioResult {
    scenario: String,
    intercept_ratio: f64,
    raw_key_length: usize,
    matching_bases_count: usize,
    sifted_key_length: usize,
    #[serde(rename = "qber")]
    mismatch_rate: f64,
    dynamic_threshold: f64,
    is_authentic: bool,
    threat_flagged: bool,
    /// First differing bit index between Alice's and Bob's sifted keys, if any.
    first_divergence: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    derived_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hmac_tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hmac_valid: Option<bool>,
    note: String,
}

fn finalize(
    scenario: &str,
    intercept_ratio: f64,
    key_length: usize,
    tx: SiftedKeyResult,
    base_threshold: f64,
    message: Option<&str>,
) -> Result<ScenarioResult, String> {
    let detector = ThreatDetector::new(base_threshold).map_err(|e| e.to_string())?;
    let eval = detector
        .evaluate_signature(tx.mismatch_rate, tx.matching_bases_count)
        .map_err(|e| e.to_string())?;

    let first_divergence = tx
        .sifted_key_bits
        .iter()
        .zip(tx.alice_sifted_bits.iter())
        .position(|(b, a)| b != a);

    let derived_secret = if eval.is_authentic {
        Some(privacy_amplification(&tx.sifted_key_bits))
    } else {
        None
    };

    let mut result = ScenarioResult {
        scenario: scenario.to_string(),
        intercept_ratio,
        raw_key_length: key_length,
        matching_bases_count: tx.matching_bases_count,
        sifted_key_length: tx.sifted_key_bits.len(),
        mismatch_rate: eval.mismatch_rate,
        dynamic_threshold: eval.dynamic_threshold,
        is_authentic: eval.is_authentic,
        threat_flagged: eval.threat_flagged,
        first_divergence,
        derived_secret,
        hmac_tag: None,
        hmac_valid: None,
        note: eval.note.to_string(),
    };

    if let (Some(secret), Some(msg)) = (&result.derived_secret, message) {
        let tag = compute_message_hmac(secret, msg.as_bytes()).map_err(|e| e.to_string())?;
        result.hmac_valid = Some(verify_message_hmac(secret, msg.as_bytes(), &tag).unwrap_or(false));
        result.hmac_tag = Some(tag);
    }

    Ok(result)
}

/// Runs one scenario with live per-batch progress events on the SSE channel.
fn execute_scenario_streaming(
    events: &broadcast::Sender<Arc<RunEvent>>,
    run_id: u64,
    scenario: &str,
    intercept_ratio: f64,
    key_length: usize,
    base_threshold: f64,
    message: Option<&str>,
    seed: u64,
    pace_ms: u64,
) -> Result<ScenarioResult, String> {
    let mut rng = StdRng::seed_from_u64(seed);
    let qkg = QuantumKeyGenerator::new(key_length).map_err(|e| e.to_string())?;
    let alice_keys = qkg.generate_eigenstates(&mut rng);

    let mut session = ChannelSession::new(intercept_ratio);
    let batch = (key_length / 100).max(1);

    for (i, &(basis, state)) in alice_keys.iter().enumerate() {
        session.transmit(basis, state, &mut rng);
        if (i + 1) % batch == 0 || i + 1 == key_length {
            // Hoeffding slack: ε = √(ln(2/δ) / 2n), δ = 0.05 (detector default)
            let n = session.matching_bases_count() as f64;
            let slack = if n > 0.0 {
                ((2.0_f64 / 0.05).ln() / (2.0 * n)).sqrt()
            } else {
                1.0
            };
            let threshold = (base_threshold + slack).min(1.0);
            let _ = events.send(Arc::new(RunEvent::Progress {
                run_id,
                scenario: scenario.to_string(),
                processed: i + 1,
                total: key_length,
                sifted: session.sifted_count(),
                mismatches: session.mismatch_count(),
                qber: session.qber(),
                threshold,
            }));
            if pace_ms > 0 && i + 1 < key_length {
                std::thread::sleep(std::time::Duration::from_millis(pace_ms));
            }
        }
    }

    finalize(scenario, intercept_ratio, key_length, session.finish(), base_threshold, message)
}

#[derive(Debug, Clone, Serialize)]
struct RunResponse {
    run_id: u64,
    /// The seed actually used (echoed so the dashboard can display why a
    /// run is reproducible: a typed-in seed re-produces identical results).
    seed: u64,
    results: Vec<ScenarioResult>,
    authenticated_message: Option<String>,
}

async fn health() -> &'static str {
    "ok"
}

/// Which port the server actually bound (differs from the request only after
/// a port-fallback). The frontend uses this to locate a fallback server.
async fn server_info(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "port": state.bound_port.load(std::sync::atomic::Ordering::Relaxed)
    }))
}

pub(crate) fn bad_request(msg: String) -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": msg })))
}

fn internal_error(msg: String) -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": msg })))
}

fn random_seed() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(42)
}

fn validate_common(key_length: usize, base_threshold: f64) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if !(MIN_KEY_LENGTH..=MAX_KEY_LENGTH).contains(&key_length) {
        return Err(bad_request(format!(
            "key_length must be between {MIN_KEY_LENGTH} and {MAX_KEY_LENGTH}"
        )));
    }
    if !(0.0..=1.0).contains(&base_threshold) {
        return Err(bad_request("base_threshold must be between 0.0 and 1.0".into()));
    }
    Ok(())
}

async fn run_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RunRequest>,
) -> Result<Json<RunResponse>, (StatusCode, Json<serde_json::Value>)> {
    let key_length = req.key_length.unwrap_or(DEFAULT_KEY_LENGTH);
    let base_threshold = req.base_threshold.unwrap_or(DEFAULT_BASE_THRESHOLD);
    let pace_ms = req.pace_ms.unwrap_or(DEFAULT_PACE_MS).min(50);
    let message = req
        .message
        .unwrap_or_else(|| "SIH26141 Sensitive Financial Transaction Data".into());
    if message.len() > MAX_MESSAGE_LEN {
        return Err(bad_request(format!("message must be at most {MAX_MESSAGE_LEN} bytes")));
    }
    validate_common(key_length, base_threshold)?;

    let scenarios: Vec<(&str, f64)> = match req.intercept_ratio {
        Some(r) => {
            if !(0.0..=1.0).contains(&r) {
                return Err(bad_request("intercept_ratio must be between 0.0 and 1.0".into()));
            }
            vec![("custom", r)]
        }
        None => vec![("secure", 0.0), ("attack", 1.0)],
    };

    let run_id = state.run_counter.fetch_add(1, Ordering::SeqCst);
    let seed = req.seed.unwrap_or_else(random_seed);

    let state_clone = Arc::clone(&state);
    let response = tokio::task::spawn_blocking(move || -> Result<RunResponse, String> {
        let mut results = Vec::with_capacity(scenarios.len());
        for (i, (scenario, ratio)) in scenarios.iter().enumerate() {
            let result = execute_scenario_streaming(
                &state_clone.events_tx,
                run_id,
                scenario,
                *ratio,
                key_length,
                base_threshold,
                Some(&message),
                seed.wrapping_add(i as u64 * 0x9E37_79B9_7F4A_7C15),
                pace_ms,
            )
            .map_err(|e| format!("Scenario '{scenario}' failed: {e}"))?;
            let _ = state_clone
                .events_tx
                .send(Arc::new(RunEvent::Result { run_id, result: result.clone() }));
            results.push(result);
        }
        Ok(RunResponse {
            run_id,
            seed,
            results,
            authenticated_message: Some(message),
        })
    })
    .await
    .map_err(|e| internal_error(format!("Task join failure: {e}")))?
    .map_err(internal_error)?;

    *state.last_result.lock().unwrap() = Some(response.clone());
    let _ = state.events_tx.send(Arc::new(RunEvent::Done { run_id }));
    Ok(Json(response))
}

#[derive(Debug, Deserialize)]
struct SimulateRequest {
    /// Intercept ratios to evaluate, e.g. [0.0, 0.1, 0.5, 1.0].
    intercept_ratios: Vec<f64>,
    key_length: Option<usize>,
    base_threshold: Option<f64>,
    seed: Option<u64>,
}

#[derive(Debug, Serialize)]
struct SimulateResponse {
    run_id: u64,
    /// The seed actually used (blank seed in the UI = fresh random seed,
    /// echoed here so every chart can be attributed to its randomness).
    seed: u64,
    sweep: Vec<ScenarioResult>,
}

async fn simulate_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SimulateRequest>,
) -> Result<Json<SimulateResponse>, (StatusCode, Json<serde_json::Value>)> {
    let key_length = req.key_length.unwrap_or(DEFAULT_KEY_LENGTH);
    let base_threshold = req.base_threshold.unwrap_or(DEFAULT_BASE_THRESHOLD);
    validate_common(key_length, base_threshold)?;
    if req.intercept_ratios.is_empty() {
        return Err(bad_request("intercept_ratios must contain at least one value".into()));
    }
    if req.intercept_ratios.len() > 32 {
        return Err(bad_request("intercept_ratios must contain at most 32 values".into()));
    }
    for &r in &req.intercept_ratios {
        if !(0.0..=1.0).contains(&r) {
            return Err(bad_request("each intercept_ratio must be between 0.0 and 1.0".into()));
        }
    }

    let run_id = state.run_counter.fetch_add(1, Ordering::SeqCst);
    // Blank seed means fresh randomness here too — the dashboard labels the
    // "Seed (blank = random)" input, so a pinned default would make every
    // sweep visually identical. Callers who want reproducibility pass a seed.
    let seed = req.seed.unwrap_or_else(random_seed);

    let response = tokio::task::spawn_blocking(move || -> Result<SimulateResponse, String> {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut sweep = Vec::with_capacity(req.intercept_ratios.len());
        for (i, &ratio) in req.intercept_ratios.iter().enumerate() {
            let qkg = QuantumKeyGenerator::new(key_length).map_err(|e| e.to_string())?;
            let keys = qkg.generate_eigenstates(&mut rng);
            let tx = quantum::simulate_six_state_transmission_ratio(&keys, ratio, &mut rng);
            let result = finalize(&format!("sweep-{i}"), ratio, key_length, tx, base_threshold, None)
                .map_err(|e| format!("Sweep point {i} failed: {e}"))?;
            sweep.push(result);
        }
        Ok(SimulateResponse { run_id, seed, sweep })
    })
    .await
    .map_err(|e| internal_error(format!("Task join failure: {e}")))?
    .map_err(internal_error)?;

    Ok(Json(response))
}

async fn sse_handler(
    State(state): State<Arc<AppState>>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, std::convert::Infallible>>> {
    let rx = state.events_tx.subscribe();
    let replay = state.last_result.lock().unwrap().clone();
    let stream = BroadcastStream::new(rx).filter_map(move |item| match item {
        Ok(ev) => Some(Ok::<_, std::convert::Infallible>(Event::default().data(
            serde_json::to_string(&*ev).unwrap_or_default(),
        ))),
        Err(BroadcastStreamRecvError::Lagged(n)) => Some(Ok::<_, std::convert::Infallible>(
            Event::default().data(format!("{{\"type\":\"lagged\",\"skipped\":{n}}}")),
        )),
    });
    let replay_events = tokio_stream::iter(replay).map(|r| {
        Ok::<_, std::convert::Infallible>(Event::default().data(
            serde_json::to_string(&RunEvent::Result { run_id: r.run_id, result: r.results.last().unwrap().clone() })
                .unwrap_or_default(),
        ))
    });
    Sse::new(tokio_stream::StreamExt::chain(replay_events, stream)).keep_alive(
        KeepAlive::new()
            .interval(std::time::Duration::from_secs(15))
            .text("keep-alive"),
    )
}

#[tokio::main]
async fn main() {
    let (events_tx, _) = broadcast::channel(1024);

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_PORT);

    // Serve the built frontend when present (frontend/dist), else API-only.
    let static_dir = std::env::var("FRONTEND_DIST")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../frontend/dist")
        });

    // Persistent QDS security-event log next to the executable's workspace.
    let qds_log_path = std::env::var("QDS_EVENT_LOG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("qds_events.jsonl"));
    let qds_state = QdsStateHolder::new(qds_log_path.clone());

    let state = Arc::new(AppState {
        events_tx,
        last_result: Mutex::new(None),
        run_counter: AtomicU64::new(1),
        qds: Mutex::new(qds_state),
        qds_log_path,
        // Patched once the listener is bound (fallback may change it).
        bound_port: std::sync::atomic::AtomicU16::new(port),
    });

    let app = Router::new()
        .route("/api/health", get(health))
        .route("/api/server-info", get(server_info))
        .route("/api/run", post(run_handler))
        .route("/api/simulate", post(simulate_handler))
        .route("/api/events", get(sse_handler))
        .merge(qds_router())
        .layer(CorsLayer::permissive())
        .with_state(Arc::clone(&state));

    let app = if static_dir.join("index.html").exists() {
        app.fallback_service(
            tower_http::services::ServeDir::new(&static_dir)
                .append_index_html_on_directories(true),
        )
    } else {
        eprintln!("Note: no frontend build at {} — API-only mode.", static_dir.display());
        app
    };

    // Bind with a clear error message and, on Windows, a fallback: OS error
    // 10013 (PermissionDenied) happens when another process holds the port
    // OR when Windows excluded port ranges (Hyper-V / WinNAT reservations)
    // block it entirely — common right after a reboot. Fall back to the next
    // few ports so a demo never dies on a stale reservation.
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            const MAX_FALLBACKS: u16 = 10;
            eprintln!(
                "warning: could not bind {addr} (os error 10013 — port held by another process or blocked by a Windows reserved port range)"
            );
            let mut bound = None;
            for offset in 1..=MAX_FALLBACKS {
                let candidate = SocketAddr::from(([127, 0, 0, 1], port + offset));
                match tokio::net::TcpListener::bind(candidate).await {
                    Ok(l) => {
                        eprintln!("falling back to {candidate}");
                        bound = Some(l);
                        break;
                    }
                    Err(_) => continue,
                }
            }
            bound.unwrap_or_else(|| {
                panic!(
                    "failed to bind port {port} or any of the next {MAX_FALLBACKS} ports — free the port (netstat -ano | findstr {port}) or pick another: PORT=<port> cargo run -p server"
                )
            })
        }
        Err(e) => panic!("failed to bind port {port}: {e}"),
    };

    let bound_addr = listener.local_addr().expect("listener has a local address");
    state.bound_port.store(bound_addr.port(), std::sync::atomic::Ordering::Relaxed);
    if bound_addr.port() != port {
        // Publish the actual bound port so the dashboard can find the API
        // even after a fallback: the frontend probes /server-port.json
        // (served as a static asset from frontend/dist) when its same-origin
        // health check fails.
        let manifest = serde_json::json!({
            "requested_port": port,
            "actual_port": bound_addr.port(),
            "reason": "requested port unavailable (held by another process or blocked by a Windows reserved port range)"
        });
        let port_file = static_dir.join("server-port.json");
        match std::fs::write(&port_file, manifest.to_string()) {
            Ok(()) => eprintln!(
                "NOTE: serving on http://{bound_addr} instead of http://127.0.0.1:{port} — wrote {}",
                port_file.display()
            ),
            Err(e) => eprintln!(
                "NOTE: serving on http://{bound_addr}; could not write port manifest ({e}) — open this URL manually"
            ),
        }
    } else {
        // Clean up any stale manifest from a previous fallback run.
        let _ = std::fs::remove_file(static_dir.join("server-port.json"));
    }
    eprintln!("SIH26141 API server listening on http://{bound_addr}");
    eprintln!("Frontend: {}", static_dir.display());

    axum::serve(listener, app).await.expect("server error");
}
