# SIH26141 Judging Book — Quantum-Secured Pipeline

**One document to walk into the judging round with.** It consolidates the
pitch (`JUDGE_PITCH.md`), the full guide (`PROJECT_GUIDE.md`), the formal
model (`QDS_MATH_MODEL.md`), and the run instructions
(`DASHBOARD_RUN_GUIDE.md`) — with the verified status of this exact build.

**Build status (verified Sept 12, 2026, on this machine):**

| Check | Result |
|---|---|
| `cargo test --workspace` | **35 passed, 0 failed** |
| `cargo build --workspace` | zero warnings |
| Frontend build (`tsc -b && vite build`) | clean, no type errors |
| Live endpoint smoke test | all 11 endpoints OK (QKD run, sweep, SSE, QDS setup/sign/verify/attacks/forgery-analysis/metrics/events, static dashboard) |
| Parameter responsiveness (UI) | verified: 50k vs 20k qubits change sifted counts; 25% vs 15% threshold moves the decision line; blank seed = fresh randomness per run; typed seed = bit-identical reproduction (shown in the event log as `seed <n> · <qubits> qubits · threshold <x>%`) |
| Demo-path behavior | QBER = 0.337 ≈ 1/3 on full attack ✓ · all 5 QDS attacks rejected ✓ · HMAC verified on secure channel ✓ · audit log written ✓ |

---

## 1. The one-page summary (say this first)

Modern signatures (RSA, ECDSA) die to Shor's algorithm; "harvest now,
decrypt later" is already happening. This project is a **single software
framework with two integrated quantum-security layers**, security from
**physics, decisions from statistics, zero AI/ML**:

1. **Six-state QKD** — distributes a shared secret over a simulated quantum
   channel. Eavesdropping is *detectable, not preventable*: intercept-resend
   forces QBER → f/3 (f = fraction intercepted). A two-sided **Hoeffding
   bound** sets a finite-sample threshold; compromised channels **abort**
   key distillation; clean channels distill a 256-bit key via SHA-256
   privacy amplification and HMAC-authenticate messages.
2. **Teleportation-based QDS** — signs messages with Bell-pair
   entanglement + quantum teleportation (Pauli corrections), per
   Gottesman–Chuang 2001 verdict semantics (**1-ACC / 0-ACC / REJ** +
   transferability/"Charlie consensus"). Forgery requires guessing every
   Bell outcome: **P(forgery) = 4^(−qλ)** ≈ 2.9×10⁻³⁹ at default params.
   All five threat classes — forgery, impersonation, replay, channel
   tampering, unauthorized verification — are detected by explicit
   threshold rules, with a **persistent JSONL audit log**.

A Rust API server (axum) drives both layers; a React dashboard makes every
step visible live — converging QBER/threshold lines, a teleportation trace
table, and a λ-scaling forgery-probability chart.

The three papers in the problem statement are implemented specifically, not
"inspired by": GC01's verdict semantics and transferability criterion;
Singh et al. 2023's sign → teleport → validate pipeline (nonce ledger ≙
double-spend resistance); Weng et al. 2021's six-state encoding and
mismatch-rate thresholds, implemented **as a second complete QDS scheme**.

---

## 2. Deliverables map (their table → our artifacts)

| Deliverable | Where |
|---|---|
| 1. Math model of teleportation-based QDS | `docs/QDS_MATH_MODEL.md` (Bell states, teleportation derivation, C1/C2 verification equations, forgery theorem, complexity) |
| 2. Threat-detection framework | `detection` crate (Hoeffding) + `qds::verify` + `qds::six_state::classify` — all 5 attack classes, no ML |
| 3. Signature generation & verification module | `qds::sign`/`verify`/`verify_transferability`; six-state twin `sign_six_state`/`verify_six_state` |
| 4. Attack simulation module | `qds::attacks` (5 classes) + QKD intercept-resend; tamper fraction adjustable; all tested |
| 5. Performance evaluation | `qds::metrics` + `/api/qds/metrics` + dashboard panel: accuracy, detection rate, false alarms, forgery prob. (MC vs theory), timings; seeded/reproducible |
| 6. Software framework / prototype | `server` (REST + SSE) + `frontend` dashboard + `qds_events.jsonl` audit log |

Constraints: no AI/ML ✓ · deterministic acceptance of honest signatures ✓
(theorem + test) · low complexity ✓ (O(qλ), ~20–30 µs measured) ·
information-theoretic verification path ✓ · prototype + docs ✓.

---

## 3. Numbers you must know cold (with one-line derivations)

| Number | Value | Why |
|---|---|---|
| Full intercept-resend QBER | **1/3** | Eve wrong basis 2/3 × wrong bit 1/2 (six-state, 3 bases) |
| Partial eavesdropping QBER | **f/3** | linearity; asserted by unit test |
| Detection crossover (20k qubits, base 15%) | **f ≈ 50–55%** | measured on this build: 50% → 16.05% < 16.66% ≤ 18.97% @ 55% |
| Hoeffding margin | **ε = √(ln(2/δ)/2n)**, δ=0.05 | shrinks like 1/√n |
| Sifting yield | **~1/3** | 3 bases; 20k qubits → ~6,650 sifted (measured 6,649) |
| Forgery probability | **4^(−qλ)** | guess both bits at each of qλ positions |
| At (16, λ=4) | **≈ 2.9×10⁻³⁹** | 4⁻⁶⁴ |
| 128-bit security | λ ≥ 4 at q=16 | 4⁻¹²⁸ ≈ 2⁻²⁵⁶ at λ=8 |
| MC validation | 20,000 trials → 0.25 @ (1,1) | matches theory exactly |
| Per-op cost | **~20–30 µs** sign/verify | measured; O(qλ) |
| Evaluation accuracy | **> 99.9%**, 0 false alarms | 200 trials, seed 42 |
| Tests | **35 passing** | 13 qds unit + 16 qds int + 3 quantum + 3 QKD int |

**Why the metrics panel shows 99.9% and not 100%** (judges may probe):
finite-sample tail of a bounded-error statistical test — the 30%-tampering
scenario sits ~2.7σ above the rejection threshold at n≈400 (one slip in 200
is the expected Binomial tail), and the evaluation's teleport-impersonation
probe uses q=8 digest bits (collision prob 2⁻⁸ = 1/256). Both tails shrink
exponentially with their security parameter. Full write-up:
`PROJECT_GUIDE.md` §3.9, `QDS_MATH_MODEL.md` §9.1.

---

## 4. The 5-minute demo script (full script in JUDGE_PITCH.md)

Start the app first: `cargo run -p server` → http://127.0.0.1:8080
(see `DASHBOARD_RUN_GUIDE.md`).

1. **QKD catch-the-eavesdropper (2 min)** — *Run Secure + Attack*.
   Left card: QBER 0.00%, AUTHENTIC, key + HMAC. Right card: red line
   converges to exactly 1/3, THREAT FLAGGED, "key distillation aborted".
   Narrate the dashed Hoeffding thresholds tightening — "a formula you can
   write on a napkin, not a model you have to trust."
2. **Sweep (1 min)** — *Run parameter sweep*. Bars track theory f/3; the
   threshold crossing sits near 50–55% at the default 20k qubits. "The
   theory *predicts* the simulation — that's what makes this a verification
   tool." Click it twice with the seed box blank: the bars wiggle between
   runs (fresh randomness) — then type seed 777 in the Seed box, run twice,
   and point at the event log: identical `seed 777` provenance, identical
   numbers. That's the reproducibility-for-audit story in ten seconds.
3. **QDS Signature Lab (2–3 min)** — ① keys (P(forgery) < 10⁻³⁹ chip) →
   ② sign (teleportation trace table: Bell outcomes 00–11, Pauli
   corrections I/X/Z/XZ, Bob verified 1-ACC, single-use nonce) → ③ all 5
   attacks rejected → ④ forgery-analysis chart (each λ ≈ ×1000 harder to
   forge) → ⑤ evaluation panel (accuracy > 99.9%, zero false alarms,
   microsecond timings, seeded/reproducible).
4. **If asked**: open `qds_events.jsonl` in Notepad — every sign/verify/
   attack persisted with timestamp + verdict (deliverable: logging).
5. **Fallback if the browser misbehaves**: `cargo run -p main_app` — same
   engine, terminal output, keep narrating.

---

## 5. Judge Q&A — the six that actually get asked

**"Is this a real quantum computer?"** — No; a faithful classical
simulation of the protocol's information structure (like a flight
simulator for aerodynamics). The problem statement asks for a software
framework with mathematical modelling, attack simulation and security
analysis — that's exactly this.

**"How is this different from post-quantum cryptography?"** — PQC is
*computational* security (new hard math). Ours is *information-theoretic*:
security from physics, valid against unbounded adversaries.
Complementary; our QKD keys can even feed PQC/AES.

**"Where's the AI/ML?"** — The problem statement forbids relying on it.
Every verdict is an explicit threshold rule on measured mismatch rates —
more explainable than any model: I can derive each alarm on a whiteboard.

**"What stops Eve intercepting a little?"** — Nothing, and that's honest
physics: partial interception raises QBER proportionally; the Hoeffding
margin tightens as samples accumulate; privacy amplification compresses
away residual information. Detection-vs-yield is *the* QKD trade-off and
our sweep chart shows it live.

**"Isn't SHA-256 a weakness if you claim information-theoretic security?"**
— The verification path (XOR correlation checks) needs no computational
assumption. SHA-256 appears only in auxiliary roles (commitment, message
binding) analyzed as a random oracle — the standard treatment — and the
simplified PA step is flagged honestly in the docs.

**"Forgery probability — where does 10⁻³⁹ come from?"** — Two secret bits
per position; a forger guesses both at every one of 64 positions:
(1/4)⁶⁴ ≈ 2.9×10⁻³⁹. A 20k-trial Monte-Carlo on small parameters
converges to exactly the theoretical 1/4 per position — the chart in
step ④ shows theory and simulation agreeing.

Deeper answers for all of these: `JUDGE_PITCH.md` Part C.

---

## 6. Honest limitations (volunteer two, it builds trust)

1. Classical simulation (ideal Bell pairs, noiseless channel unless an
   attack injects disturbance) — models the information structure
   faithfully, no physical qubits.
2. No error-correction stage and simplified privacy amplification
   (fixed SHA-256, not universal₂ sized by entropy budget) — both marked
   in code and docs with the roadmap item they map to.

Full list (8 items) with roadmap: `PROJECT_GUIDE.md` Part 6.

---

## 7. Document index

| Doc | Use it for |
|---|---|
| `DASHBOARD_RUN_GUIDE.md` | **Starting the app** — prerequisites, commands, smoke test, troubleshooting |
| `DASHBOARD_GUIDE.md` | **What everything on the page means** — element-by-element explainer for both QKD and QDS sections, with a parameter-responsiveness matrix |
| `JUDGE_PITCH.md` | The full spoken script: opener, demo narration, Q&A, flashcards, room checklist |
| `PROJECT_GUIDE.md` | Complete theory from zero + codebase walkthrough + verification state |
| `QDS_MATH_MODEL.md` | Formal model: Bell/teleportation derivation, C1/C2, forgery theorem, literature mapping |
| `../README.md` | Repo overview, API table, quickstart |

**Final pre-flight:** tests pass → server up → pill green → 5-click smoke
test → laptop charged, browser zoom up, Slack closed. You're ready.
