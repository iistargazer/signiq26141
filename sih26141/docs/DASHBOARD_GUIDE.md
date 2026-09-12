# Dashboard Explainer — Every Element, Both Layers (QKD + QDS)

**What this is:** a complete, element-by-element explanation of everything
visible on the SIH26141 dashboard at `http://127.0.0.1:8080` — what each
control does, what each number means, where it comes from in the backend,
and what should (and shouldn't) change when you interact with it.

**How to read this doc:** sections follow the page top-to-bottom. QKD =
the key-distribution half of the page (sections 2–7). QDS = the Signature
Lab half (section 8 — the deepest section, per the problem statement's
focus). Section 9 is a responsiveness matrix: what changes when you touch
each control — use it to verify the app is behaving before a demo.

*Companion docs:* `DASHBOARD_RUN_GUIDE.md` (how to start the app),
`JUDGING_BOOK.md` (what to say), `PROJECT_GUIDE.md` (full theory),
`QDS_MATH_MODEL.md` (the formal math behind section 8).
Yes.
---

## 1. Page orientation

One page, seven regions, top to bottom:

```
┌──────────────────────────────────────────────────────────┐
│ ① HEADER        title · API pill · Run button             │
│ ② PARAMETERS    sliders & inputs for the QKD experiment   │
│ ③ STATUS CARDS  verdict per scenario (secure / attack)    │
│ ④ LIVE MONITOR  streaming QBER chart + per-scenario stats │
│ ⑤ SWEEP PANEL   QBER vs eavesdropping-intensity bars      │
│ ⑥ KEY MATERIAL  derived secret + HMAC result              │
│ ⑦ QDS LAB       ① keys ② sign ③ attacks ④ forgery ⑤ eval  │
│    FOOTER       "educational prototype" disclaimer        │
└──────────────────────────────────────────────────────────┘
```

Everything talks to one Rust server (axum) on one port. The QKD half
(①–⑥) streams live over Server-Sent Events while a run executes; the QDS
half (⑦) is request/response — each button click is one API call, and
every click leaves an entry in the persistent audit log
(`qds_events.jsonl`).

---

## 2. Header

| Element | What it does | Behind the scenes |
|---|---|---|
| **Title + subtitle** | Identifies the project: six-state QKD + Hoeffding-bound detection. | static |
| **● API online pill** | Green = browser can reach the server. Gray "checking…" = probing. Red "API offline" = no server. | Polls `/api/health` every 10 s. If same-origin fails, it auto-discovers a fallback port (reads `server-port.json`, then probes 8081–8090) and retargets silently — the pill turns green by itself. |
| **Run Secure + Attack** (button) | Starts the QKD simulation: two scenarios back-to-back — a clean channel and a fully intercepted one. Disabled while running. | `POST /api/run` with all ② parameters. Progress streams back on `/api/events` (SSE); the button re-enables on the `done` event. In custom-ratio mode (see ②) it reads "Run Custom Scenario". |

**Demo tip:** point at the pill first — "full stack, one port" — then click Run.

---

## 3. Experiment Parameters (QKD controls)

Every control here affects the **next** run. The event log (section 4)
echoes the values actually used for each run.

| Control | Range / default | What it really does |
|---|---|---|
| **Key length** | 1,000–100,000 qubits (default 20,000) | How many qubits Alice prepares and sends. More qubits ⇒ more sifted bits (~1/3 survive) ⇒ tighter Hoeffding margin (ε ∝ 1/√n) ⇒ better detection. *This is the detection-vs-yield trade-off made tangible.* |
| **Base QBER threshold** | 0–50% (default 15%) | The noise/alarm line before statistical correction. The real decision uses `base + ε(n)`. Lower = more sensitive (flags weaker attacks, risks false alarms on noise); higher = tolerant. The dashed "base %" line on the live chart tracks this slider. |
| **Streaming pace** | 0–20 ms/batch (default 6) | Artificial per-batch delay so the live chart is watchable. Pure theater — compute itself is microseconds. Set 0 for instant results. |
| **Custom attack ratio** (checkbox) | off | Replaces the two canonical scenarios (clean + full attack) with ONE scenario at your chosen interception fraction. The status cards and chart reconfigure to a single "Custom Intercept Ratio" card. |
| **Eve intercept ratio** (slider, custom mode only) | 0–100% (default 30%) | Fraction of qubits Eve measures-and-resends. Expected QBER ≈ ratio/3 (30% → ~10%). |
| **Seed (blank = random)** | number or blank | **Blank = fresh randomness every run** — the server draws a time-based seed and echoes it in the event log. **Typed = fully reproducible**: same seed + same parameters re-produce bit-identical results (keys, QBER, signatures). The placeholder shows the last used seed so you can reproduce any run. Judges ask about this: seeded runs are the audit story. |
| **Authenticated message** | free text | The payload HMAC-signed with the distilled key on the secure scenario (and shown in the Key Material panel). Compromised channels produce no key ⇒ no HMAC. |

**Common trap:** if a seed is typed in, results are *supposed* to repeat
identically. Blank the box to see fresh randomness. (Each run logs
`seed <n> · <qubits> qubits · threshold <x>%` — if those don't match the
sliders, the page is stale; hard-refresh.)

---

## 4. Status cards (one per scenario)

Two cards in default mode — **Secure Channel** (green accent) and
**Intercept-Resend Attack** (red accent); one card in custom mode.

| Element | Meaning |
|---|---|
| **Verdict chip** | `✓ AUTHENTIC` — measured QBER is at/below the dynamic threshold ⇒ channel presumed clean, key distilled. `✗ THREAT FLAGGED` — QBER exceeded the bound ⇒ eavesdropper presumed, **key distillation aborted** (no key exists at all). `streaming…` / `idle` while not finished. |
| **Measured QBER** | Fraction of *sifted* bits Bob got wrong. Clean channel: 0.00% (deterministic in the noiseless sim). Full attack: →1/3 (six-state physics: Eve wrong basis 2/3 × wrong bit 1/2). |
| **Dynamic threshold** | `base + √(ln(2/δ)/2n)` at final sample size (δ=0.05). The statistically safe alarm line — watch it converge downward during a run. |
| **Sifted key bits** | Bits surviving basis sifting (~1/3 of raw; 20,000 → ~6,650). |

Below each card on a threat: *"Eavesdropping detected — QBER exceeds the
finite-key bound. Key distillation aborted."* — the abort **is** the
security feature: no compromised key ever exists to leak.

---

## 5. Live Channel Monitor

Appears while/after a run.

**Per-scenario stat blocks:**

| Stat | Meaning |
|---|---|
| **status chip** | `channel stable` vs `⚠ QBER above threshold` (live comparison as data streams) |
| **transmitted %** | progress through the raw qubits |
| **sifted bits** | surviving bits so far |
| **mismatches** | wrong bits among sifted so far |
| **live QBER** | running mismatch rate |

**The chart** — the demo centerpiece:

- **Solid lines** — live QBER per scenario. Secure: flat at 0%. Attack:
  climbs and converges to ≈33.3%.
- **Dashed lines (same colors)** — the Hoeffding-adjusted threshold at the
  current sample size: starts lenient (few samples) and **tightens toward
  the base threshold** as n grows. The visible convergence *is* the
  finite-key statistics lesson.
- **Gray dashed "base X%" line** — the base threshold from the slider
  (label updates with the slider).

**Event log** (right/below): timestamped verdict lines, newest first.
Every run/sweep adds a **provenance line**:
`Run #12: 1/2 scenarios authentic · seed 1844674… · 50,000 qubits ·
threshold 25%` — the exact randomness and parameters used, so any result
can be reproduced or audited.

---

## 6. Sweep panel — "QBER vs. Eavesdropping Intensity"

Click **Run parameter sweep**: measures the full attack curve by
simulating 11 interception levels (0%–100% in 10% steps) at the current
key length.

| Element | Meaning |
|---|---|
| **Blue bars (Measured QBER)** | simulated result at each intercept ratio |
| **Dark bars (Theoretical ratio/3)** | the physics prediction QBER = f/3 |
| **Red dashed threshold line** | the Hoeffding threshold at that sample size; bars crossing it are flagged |

**What to say:** the blue and dark bars track each other without tuning —
"the theory *predicts* the simulation." Detection crossover at the default
20k qubits and 15% base: **50–55% interception** (below that, Eve's added
QBER hides under the statistically-safe band — the honest detection-vs-
yield trade-off; more qubits push the crossover lower).

The sweep uses the seed box rules too (blank = fresh randomness per
sweep; typed = identical bars every time, provenance logged).

---

## 7. Key Material & Message Authentication panel

Appears after a run completes — one block per scenario.

**Secure scenario (clean channel):**

| Element | Meaning |
|---|---|
| `✓ secure key established` | detector accepted the channel |
| **Derived secret (SHA-256 PA)** | the 256-bit key distilled from all sifted bits (privacy amplification; simplified — real QKD uses a universal₂ hash sized by an entropy budget, flagged in docs) |
| **HMAC-SHA256 tag** | authentication tag over your message text with that key |
| `verified` chip | tag recomputed and matched in **constant time** (timing-attack-safe comparison) |

**Attack scenario (compromised channel):**

> `✗ key distillation aborted` — *Channel compromised at 33.69% QBER —
> first divergent sifted bit at index #2. No shared secret produced.*

The **first divergent bit index** is forensic detail: where Alice's and
Bob's keys first disagree — evidence of disturbance, and proof that no
secret was distilled.

---

## 8. ⚛ QDS Signature Lab (the deep section)

The teleportation-based Quantum Digital Signature lab. Five numbered
steps, top to bottom. Participants: **Trent** (notary/distribution
center), **Alice** (signer), **Bob** (verifier), **Charlie** (second
verifier for transferability). Formal math: `QDS_MATH_MODEL.md`.

### 8.1 Step ① — "Generate quantum keys"

**What happens on click:** Trent (`Trent::setup`) creates fresh secret
Bell-correlation tables A1, A2 — for each of q×λ positions two hidden
bits realized by Bell pairs shared with Alice — and publishes only their
hash. Any previous signature state is cleared (you must re-sign after
re-keying).

| Element | Meaning |
|---|---|
| **`Key: 16 qubits × λ=4 Bell rounds`** | Security parameters: q signature qubits × λ Bell-pair depth = 64 secret positions per signature. Defaults are the API's (16, 4). |
| **`P(forgery) < 10^-38` chip** | Whole-signature forgery bound: a forger must guess both hidden bits at every position: P = (1/4)⁶⁴ = 4⁻⁶⁴ ≈ 2.9×10⁻³⁹. The chip shows the ceiling exponent. |
| **`27b04e6e8b728a…` (commitment)** | The public key: SHA-256(A1‖A2‖λ). Only a commitment is public — the correlations themselves never leave Trent/Alice. **Changes on every regeneration** (fresh randomness) — quick visual check the button works. |

### 8.2 Step ② — "Sign via teleportation"

**What happens on click:** for each of the 64 positions (i,j), Alice
teleports the payload bit `m_i ⊕ A1[i][j]` (m = SHA-256 of your message,
one bit per qubit): a Bell measurement with a uniformly random outcome
she cannot choose, two classical bits sent, Bob applies the Pauli
correction. She publishes two signature bits per position:
`x = m_i ⊕ A1[i][j]` (message binding) and `z = A1[i][j] ⊕ A2[i][j]`
(secondary-correlation binding). Then Bob verifies on delivery — which
**consumes the single-use nonce**.

| Element | Meaning |
|---|---|
| **`✓ Bob verified · 1-ACC (transferable)`** | Bob's on-delivery verification passed with zero mismatches ⇒ verdict 1-ACC per Gottesman–Chuang: valid **and** safe to forward to other verifiers. (`✗ delivery failed` would mean the quantum channel corrupted the signature in transit.) |
| **`nonce 1 (single-use)`** | Trent's replay-defense registry number, consumed by Bob's acceptance. Re-presenting this signature later = replay = rejected. Nonces increment per signing session and reset when keys are regenerated. |
| **`128 signature bits`** | 2 published bits × 64 positions. |
| **Teleportation trace table** | The actual teleportation log, first 6 qubits: **qubit** = position; **Bell outcome** = the 2-bit measurement result (00/01/10/11, uniformly random — the signature's randomness source); **Pauli correction** = what Bob applies (I/X/Z/XZ, mapped from the outcome); **raw bit** = Bob's bit *before* correction; **corrected** = after — always equals the intended payload (ideal teleportation; watch raw flip exactly when the correction is X or ZX). |
| **Signature (correction bits)** | The published signature as hex (0/1 bytes): 128 bits. **Bound to the message** — change one character of the message and re-sign: the signature is completely different (the message-hash bits feed every position). |
| **Tamper fraction slider (0–100%, default 50%)** | Controls scenario ③'s channel-tampering attack: what fraction of teleported qubits Eve disturbs in flight. Each disturbed position flips one published bit, so mismatches scale ∝ fraction (0% → 0 mismatches and the tampered signature is honestly *accepted* — no disturbance, no false alarm; 100% → every position mismatches). |

### 8.3 Step ③ — "Launch all 5 attacks"

Runs all five threat classes from the problem statement against the last
genuine signature, each verified through the same `qds::verify` pipeline
and appended to the audit log. Every row:

- **name + verdict chip** (`REJ` / `0-ACC` / `1-ACC` — genuine signatures
  get 1-ACC; every attack here must show REJ),
- **accept/reject chip** (`✓ rejected` is the *good* outcome for an
  attack; `✗ accepted (bad!)` would mean a missed attack — expect none),
- **description** of the attacker's move,
- **statistics line** — real measured evidence from the verification
  equations: `mismatches/total positions · match ratio`. One nuance:
  **replay** shows *"blocked before statistics — nonce/commitment check"*
  — correct and worth saying aloud: a replayed signature is caught by the
  nonce registry *before* any statistics run, because nonce reuse IS the
  attack.
- **Charlie consensus** where applicable — the transferability re-check
  (GC01 security criterion 2).

| Row | What the attacker does | Why it fails (what the stats show) |
|---|---|---|
| **Forgery (guessed Bell outcomes)** | Fabricates all 128 correction bits uniformly at random under a fresh nonce | Both verification equations (C1: x⊕m_i =? A1; C2: z⊕A1 =? A2) are random per position ⇒ ~75% mismatch (e.g. 49/64). Success would need ALL positions right: 4⁻⁶⁴ ≈ 10⁻³⁹. |
| **Impersonation (signature transplant)** | Takes the genuine signature and presents it as covering a *different* message (e.g. "transfer 999 QCO") | The message-hash bits change ⇒ C1 (message binding) fails wherever the digests differ (~half of positions — e.g. 24/64). Signatures are mathematically welded to their message. |
| **Replay (nonce reuse)** | Re-presents the accepted signature verbatim | Nonce registry: already consumed ⇒ rejected **before statistics**. This is the double-spend defense from the blockchain paper. |
| **Channel tampering (qubits disturbed in flight)** | Genuine bits, but the slider-fraction of teleported qubits disturbed | Disturbed positions decode inconsistently ⇒ mismatch rate ∝ tamper fraction, exceeding the rejection threshold above ~10%. Slide the slider and watch the mismatch count climb 0 → 64. |
| **Unauthorized verification (no key material)** | A party without Trent's correlation tables attempts verification of a captured signature | The attempt is flagged as its own threat class; the re-presented bits also fail statistics (same ~62% match as a transplant) on a fresh nonce. No verdict reached without key material can be trusted. |

**Why fresh nonces for impersonation/unauthorized but not replay:** the
genuine nonce was consumed by Bob's delivery acceptance; re-presenting it
is definitionally replay. Impersonation and unauthorized rows are given
fresh nonces deliberately so their *statistical* failure modes are
visible rather than masked by the nonce check — five rows, five distinct
teachable failure reasons.

### 8.4 Step ④ — Forgery probability analysis

**What happens on click:** `GET /api/qds/forgery-analysis` — a
20,000-trial Monte-Carlo at small parameters (q=8, λ=1) plus the theory
curve.

| Element | Meaning |
|---|---|
| **Hint line** | States the law P = (1/4)^(qubits×λ) and reports MC vs theory (MC ≈ 0.0 at these params — one success would already be lucky; the test suite validates MC≈0.25 where it's measurable). |
| **Bars (log₁₀ P, λ=1..8)** | Each extra Bell round λ multiplies forgery difficulty ×~1,000 (one more quarter: 10^log10(4) ≈ ×1,000). |
| **Green "128-bit security" line** | log₁₀(2⁻²⁵⁶) = −77… shown at −30 on the λ-axis for readability; the chip in ① carries the exact bound. Crossover ≈ λ=4 at q=16 — "we exceed 128-bit at λ=4." |

This panel is **deliberately static** — it plots a theory curve; it
doesn't respond to the other controls (that's by design, not a bug).

### 8.5 Step ⑤ — Performance evaluation (Lap 2 metrics)

**What happens on click:** `GET /api/qds/metrics?trials=200&seed=42` —
the repeatable evaluation engine over **both** QDS schemes (the
teleportation pipeline AND the six-state Weng-et-al scheme that shares
the QKD layer's encoding).

| Metric (both cards) | Meaning |
|---|---|
| **Verification accuracy** | fraction of legitimate+attack events classified correctly (expect >99.9%) |
| **Detection rate** | TP/(TP+FN) over attack events |
| **False positives / negatives** | false alarms on legitimate signatures (expect 0) / missed attacks (expect 0–1 — the finite-sample tail, see §3.9 of the project guide) |
| **Forgery probability (MC vs theory)** | empirical guessed-signature success vs 4^(−qλ) |
| **Per-class detection (six-state card)** | detection % for each of the 5 attack classes in the six-state scheme |
| **sign / verify** | wall-clock per operation (~20–30 µs — the "low complexity" deliverable, measured not claimed) |

**Note:** this panel is **seeded and deterministic by design** (trials=200,
seed=42) — clicking it twice gives identical numbers, which is the point:
an evaluation an auditor can reproduce. The event log records each
evaluation run.

### 8.6 "Theoretical basis & references" (collapsible)

Maps every mechanism to its paper: Gottesman–Chuang 2001 (verdict
semantics 1-ACC/0-ACC/REJ, transferability), Singh et al. 2023
(sign→teleport→validate pipeline, Ta/Tb thresholds ≙ c1/c2, replay
resistance), Weng et al. 2021 (six-state encoding, mismatch-rate
thresholds — implemented as the second full scheme). Good "where's the
literature?" moment.

---

## 9. Responsiveness matrix — what should change when

Use this to sanity-check the app before a demo. "By design" = correct
behavior that merely looks static.

| You do this | This must change | This intentionally doesn't |
|---|---|---|
| Drag **Key length**, run | sifted bits (~n/3), threshold (ε(n)), event-log provenance; sweep bars recompute | secure QBER (0% is the physics), attack QBER (~33% is the physics) |
| Drag **Base threshold**, run | dynamic threshold & verdict margins; live-chart "base %" line label+position | QBER itself (threshold doesn't touch physics) |
| Toggle **Custom ratio** + slider, run | cards collapse to one "Custom Intercept Ratio" card; QBER ≈ ratio/3 | — |
| **Seed**: blank vs typed | blank ⇒ fresh QBER/sifted/keys each run (log shows `random`-drawn seed); typed ⇒ identical results per identical params | — |
| Type a different **message**, run | HMAC tag (it binds the new message). The derived secret does NOT change — the key comes from the sifted bits, not the message | derived secret, QBER (message never touches the channel) |
| Click **sweep** twice (blank seed) | bar heights wiggle (fresh randomness) | theory bars (fixed f/3) |
| **① Regenerate keys** | commitment hash, all subsequent signatures, nonce counter resets | P(forgery) chip (same q×λ) |
| **② Sign** again (same message, same keys) | teleport trace (fresh Bell outcomes), nonce increments, signature hex | verdict (always 1-ACC for honest signing) |
| **② Sign** a different message | entire signature hex (message-hash bits feed every position) | — |
| Move **tamper slider**, run ③ | tampering-row mismatch count ∝ fraction (0%→0 … 100%→64) | other rows (only Eve's channel behavior changed) |
| Click **④ forgery analysis** | MC estimate re-drawn (≈0 at 20k trials) | theory bars (mathematics doesn't re-roll) |
| Click **⑤ evaluation** | nothing visible — deterministic by design (seeded); each run logged | — |

**If something in the left column doesn't move:** hard-refresh
(Ctrl+Shift+R) — a stale cached bundle is the usual culprit — and check
the event-log provenance line to confirm the parameters actually sent.

---

## 10. The audit log (`qds_events.jsonl`)

Not on the page but behind everything in the QDS lab: every setup, sign,
verification, attack, and evaluation is appended to
`sih26141\qds_events.jsonl` with an RFC3339 timestamp, kind, label,
acceptance, and full verdict detail (e.g. `Acc1 — 0 mismatches across 64
positions — 1-ACC: valid and transferable`). Open it in Notepad during
Q&A — "every event you just saw was persisted" is a listed deliverable.

---

## 11. Footer

*"Simulated six-state prepare-and-measure protocol · educational
prototype — not production cryptography."* — the honesty line. Say it
before a judge does: the framework models the quantum information
structure faithfully; it is not a hardware implementation. The full
limitations list (and what each maps to on the roadmap) is in
`PROJECT_GUIDE.md` Part 6.
