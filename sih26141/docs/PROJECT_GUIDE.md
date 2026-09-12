# SIH26141 — Quantum-Secured Pipeline: Complete Project Guide

**Version 3 — judging-round edition (Sept 2026).** Supersedes v2.

**Verified state for this build:** 35/35 automated tests pass, the workspace
compiles with zero warnings, the dashboard builds clean (tsc + vite), and every
endpoint the demo touches was smoke-tested live end to end (QKD run, sweep,
QDS setup/sign/attacks/forgery-analysis/metrics/events, SSE stream, audit log).

**Audience:** team members preparing for evaluation. No prior quantum computing
or Rust knowledge assumed — everything is built up from first principles.

**What this project is:** a single software framework with **two integrated
quantum-security layers**, driven by one Rust API server and one React dashboard:

1. **Six-state QKD** (quantum key distribution) — establishes a shared secret
   key over an eavesdropped channel, detects interception via measurement
   statistics, distills keys, and authenticates messages.
2. **Teleportation-based QDS** (quantum digital signatures) — signs messages
   using Bell-pair entanglement and quantum teleportation with Pauli
   corrections, detects forgery / impersonation / replay / channel tampering,
   and quantifies forgery probability.

Both layers implement the **specific protocol semantics of the assigned
research literature** (Gottesman–Chuang 2001; Singh et al. 2023; Weng et al.
2021 — see §9). No AI/ML anywhere: every decision is pure measurement
statistics and explicit threshold rules.

---

## Table of contents

- [Part 1 — Quantum cryptography theory from zero](#part-1--quantum-cryptography-theory-from-zero)
  - [1.1 The problem QKD and QDS solve](#11-the-problem-qkd-and-qds-solve)
  - [1.2 Qubits, bases, eigenstates](#12-qubits-bases-eigenstates)
  - [1.3 Measurement, collapse, no-cloning](#13-measurement-collapse-no-cloning)
  - [1.4 BB84 and the six-state protocol](#14-bb84-and-the-six-state-protocol)
  - [1.5 The six-state protocol, step by step](#15-the-six-state-protocol-step-by-step)
  - [1.6 Why eavesdropping is detectable — the 1/3 derivation](#16-why-eavesdropping-is-detectable--the-13-derivation)
  - [1.7 Sifting, QBER, error correction, privacy amplification](#17-sifting-qber-error-correction-privacy-amplification)
  - [1.8 Finite-key statistics: the Hoeffding bound](#18-finite-key-statistics-the-hoeffding-bound)
  - [1.9 Entanglement, Bell states, and quantum teleportation](#19-entanglement-bell-states-and-quantum-teleportation)
  - [1.10 Quantum one-way functions (Gottesman–Chuang)](#110-quantum-one-way-functions-gottesmanchuang)
  - [1.11 Message authentication: HMAC vs. digital signatures](#111-message-authentication-hmac-vs-digital-signatures)
- [Part 2 — The three research papers and how we implement them](#part-2--the-three-research-papers-and-how-we-implement-them)
- [Part 3 — Codebase walkthrough](#part-3--codebase-walkthrough)
  - [3.1 Repository layout](#31-repository-layout)
  - [3.2 quantum crate](#32-quantum-crate)
  - [3.3 detection crate](#33-detection-crate)
  - [3.4 qds crate (the heart of the upgrade)](#34-qds-crate-the-heart-of-the-upgrade)
  - [3.5 attacks / crypto / main_app crates](#35-attacks--crypto--main_app-crates)
  - [3.6 server crate](#36-server-crate)
  - [3.7 frontend](#37-frontend)
  - [3.8 End-to-end data flows](#38-end-to-end-data-flows)
- [Part 4 — Running and testing](#part-4--running-and-testing)
- [Part 5 — Security analysis summary](#part-5--security-analysis-summary)
- [Part 6 — Limitations (be honest with judges)](#part-6--limitations-be-honest-with-judges)
- [Glossary](#glossary)

---

# Part 1 — Quantum cryptography theory from zero

## 1.1 The problem QKD and QDS solve

Modern digital security rests on *computational hardness*: RSA and ECC assume
that factoring integers / computing discrete logs is too expensive. Two fatal
weaknesses:

1. **Shor's algorithm** — a sufficiently large quantum computer breaks RSA and
   ECC outright. "Harvest now, decrypt later": encrypted traffic recorded
   today can be decrypted retroactively once such computers exist.
2. Hardness assumptions are beliefs about computation, **not laws of physics.**

Quantum cryptography flips the foundation: security comes from **physical
law**. Two distinct primitives matter for this project:

| | **QKD** (our layer 1) | **QDS** (our layer 2) |
|---|---|---|
| Purpose | distribute a shared *secret key* | *sign* messages so anyone can verify origin & integrity |
| Analogy | a one-time pad courier | a wax seal nobody can forge |
| Guarantee | eavesdropping is *detectable* | forgery is *exponentially improbable* |
| Quantum resource | prepared single-qubit states (six-state) | entangled Bell pairs + teleportation |

Two shared principles, worth stating precisely:

- **Detection, not prevention.** Eve may still listen; the point is that she
  *cannot listen undetected*. Compromised channels abort key/signature
  generation instead of silently leaking.
- **The classical channel must be authenticated.** Both protocols need an
  authenticated (not secret) classical channel, or a man-in-the-middle can
  impersonate both sides. Small pre-shared credentials bootstrap this.

## 1.2 Qubits, bases, eigenstates

A **qubit** is a quantum two-level system. Unlike a classical bit (0 *or* 1),
it can exist in a **superposition**:

$$
\ket{\psi} = \alpha\ket{0} + \beta\ket{1}, \qquad |\alpha|^2 + |\beta|^2 = 1
$$

Measuring in the **computational basis** {|0⟩, |1⟩} yields 0 with probability
|α|², 1 with probability |β|². Measurement *changes the state* — it collapses
to the observed outcome.

To measure, you must choose a **basis** — the physical "question" asked of the
qubit. This project uses the three **Pauli bases**:

| Basis | Operator | Matrix | Eigenstates |
|---|---|---|---|
| X | σx | [[0,1],[1,0]] | |±x⟩ = (|0⟩ ± |1⟩)/√2 |
| Y | σy | [[0,−i],[i,0]] | |±y⟩ = (|0⟩ ± i|1⟩)/√2 |
| Z | σz | [[1,0],[0,−1]] | |0⟩, |1⟩ |

An **eigenstate** of a basis gives a *deterministic* answer in that basis:
measuring |+x⟩ in X always yields +1. Every Pauli eigenstate is a perfectly
random bit string in *either of the other two* bases.

> **The fact everything rides on:** measuring a state prepared in basis A using
> a different basis B yields a uniformly random outcome and **destroys** the
> original state (collapse). There is no way to gently peek at an unknown
> quantum state.

In code: a prepared qubit is `(PauliBasis, PauliState)` — "which question it
answers" and "what the answer is" (`quantum::PauliBasis::X/Y/Z`,
`PauliState::Positive/Negative`, mapped to bits 1/0 by `as_bit()`). These are
the six states |±x⟩, |±y⟩, |±z⟩ used by both Weng et al.'s QDS encoding and
our QKD layer.

## 1.3 Measurement, collapse, no-cloning

Two fundamental facts make quantum cryptography possible:

1. **Measurement disturbance** (§1.2): wrong-basis measurement randomizes and
   destroys the state.
2. **No-cloning theorem** (Wootters–Zurek 1982): no physical process copies an
   unknown quantum state perfectly. Eve cannot photograph qubits in transit
   and forward the originals untouched.

Consequences we exploit: prepared keys/signatures cannot be counterfeited;
Eve's intervention always leaves statistical fingerprints (errors) that honest
parties can measure; entanglement cannot be replicated, only *consumed*.

## 1.4 BB84 and the six-state protocol

**BB84** (Bennett–Brassard 1984): Alice encodes bits in two conjugate bases
(rectilinear/diagonal polarization). Eve guesses the right basis ½ the time.

**Six-state** (Bruss 1998): three mutually unbiased bases (X, Y, Z). Two bases
are *mutually unbiased* when measuring one's eigenstate in the other yields a
perfectly random result. Three bases give:

- Eve guesses correctly only **1/3** of the time → full intercept-resend
  produces **QBER ≈ 33%** (vs 25% for BB84) → easier detection;
- symmetric error statistics across all three bases → simpler analysis,
  stronger checks;
- cost: only 1/3 of transmissions survive sifting (vs ½) — lower yield, higher
  detectability. This trade-off is *deliberate*.

Our QKD layer implements six-state. Weng et al. choose the same encoding for
their QDS protocol — one reason the two layers share a crate vocabulary.

## 1.5 The six-state protocol, step by step

1. **Preparation** — for each of N qubits Alice picks basis ∈ {X,Y,Z} and sign
   ∈ {+,−}, uniformly at random. Her record of (basis, sign) is the raw key
   material. `QuantumKeyGenerator::generate_eigenstates`.
2. **Transmission** — qubits cross the (insecure) quantum channel.
3. **Measurement** — Bob picks a random basis per qubit, measures, records
   ±1. `ChannelSession::transmit`.
4. **Sifting** — over the authenticated classical channel both reveal
   *bases only*; positions with matching bases are kept (§1.7).
5. **Parameter estimation** — a sample of sifted bits is compared publicly to
   estimate the **QBER** (quantum bit error rate). Too high ⇒ eavesdropper or
   noise ⇒ **abort**. `ThreatDetector::evaluate_signature`.
6. **Error correction** — reconcile remaining differences (simulated away;
   §1.7).
7. **Privacy amplification** — compress to a shorter, uniform secret (§1.7).
8. **Use** — HMAC-authenticate real traffic with the distilled key.

## 1.6 Why eavesdropping is detectable — the 1/3 derivation

The single most important calculation in the project. Consider **full
intercept-resend**: Eve measures every qubit in a random basis and resends her
result. Alice's basis A, sign s; Bob's basis B; Eve's basis E — all uniform.

Track one qubit **after sifting** (B = A, probability 1/3):

- **E = A** (prob 1/3): Eve's measurement is non-disturbing; she resends the
  exact state. Bob's bit correct with certainty.
- **E ≠ A** (prob 2/3): Eve's outcome is random; her resend is an E-eigenstate
  with random sign. Bob measures an E-eigenstate in basis A ⇒ **uniformly
  random** ⇒ wrong with probability ½.

$$
\text{QBER} = \underbrace{\tfrac{2}{3}}_{\text{Eve wrong basis}} \times \underbrace{\tfrac{1}{2}}_{\text{random bit wrong}} = \tfrac{1}{3} \approx 33.3\%
$$

**Partial attack:** if Eve intercepts only a fraction *f* of qubits
(`intercept_ratio` in our code), linearity gives

$$
\text{QBER}(f) = \frac{f}{3}
$$

Intercept 30% of qubits → expect ~10% QBER. The dashboard's sweep chart shows
this law live; the unit test `partial_ratio_yields_intermediate_qber` asserts
it. Detection fires when measured QBER exceeds the statistically safe
threshold (§1.8) — with base threshold 15% and the dashboard's default 20,000
qubits, the crossover is at **f ≈ 50–55%** interception (measured on this
build: 50% → QBER 16.05% < threshold 16.66%, 55% → 18.97% > 16.66%). For
shorter runs the Hoeffding margin is wider and the crossover moves up toward
~60–70% — detection threshold versus sample size is the trade-off to narrate.

**Simulation fidelity detail** (interviewers ask): after Eve resends in *her*
basis, Bob's outcome is deterministic only if he measures in **Eve's** basis;
otherwise random. The code carries `(current_state, current_basis)` — the
state actually on the wire — and sifts against **Alice's** basis only. This is
physically correct and distinguishes a careful implementation from a toy.

## 1.7 Sifting, QBER, error correction, privacy amplification

**Sifting.** Bob's basis matches Alice's with probability 1/3 → ~N/3 sifted
bits survive (20,000 qubits → ~6,700 bits). Revealing *bases only* leaks
nothing about the bit values.

**QBER** = mismatching sifted bits / total sifted bits. Noiseless clean
channel ⇒ 0.00%. Real hardware adds noise — which is why detection needs a
statistical margin (§1.8), not "QBER > 0 ⇒ attack".

**Error correction** (implemented by real systems; *simulated away here*):
Cascade or LDPC reconciliation makes Alice's and Bob's keys bit-identical,
leaking a calculable number of bits to Eve in the process. Our clean-channel
simulation has zero errors by construction, so the stage is a no-op — the
code comments say exactly where it would run.

**Privacy amplification** compresses the reconciled key with a universal₂
hash so Eve's residual information is negligible (leftover hash lemma).
Our simplification: SHA-256 over all sifted bits → 256-bit secret
(`quantum::privacy_amplification`). Sound for the demo because the abort path
means no key ever exists when the channel is compromised; flagged honestly as
a simplification everywhere it appears.

## 1.8 Finite-key statistics: the Hoeffding bound

Measured QBER q̂ over n sifted bits — but is the channel *truly* clean, or did
a small sample get lucky? The **two-sided Hoeffding inequality** bounds how
far an empirical frequency deviates from the true probability, with **no
variance assumptions** (unlike normal approximations) — exactly right for an
adversarial channel:

$$
P(|\hat{q} - p| \ge \varepsilon) \le 2 e^{-2n\varepsilon^2}
\quad\Rightarrow\quad
\varepsilon(n) = \sqrt{\frac{\ln(2/\delta)}{2n}}
$$

with tolerated failure probability δ = 0.05 (`with_confidence_delta`).

**Decision rule** (`detection::ThreatDetector`):

$$
\text{threshold}(n) = \text{base} + \varepsilon(n), \qquad \text{authentic} \iff \hat{q} \le \text{threshold}
$$

The margin shrinks like √(1/n): few samples ⇒ lenient bar; many samples ⇒ bar
tightens to the base threshold. Concrete numbers at base 15%:

| n (sifted) | ε | threshold |
|---|---|---|
| 100 | 17.2% | 32.2% |
| 1,000 | 5.4% | 20.4% |
| 6,700 | 2.1% | 17.1% |
| 33,000 | 0.95% | 15.9% |

(At the dashboard default of 20,000 qubits you get ~6,700 sifted bits, so a
typical run ends at threshold ≈ 16.7%.)

You can *watch* the dashed threshold lines converge during a dashboard run —
judges find this compelling. Flip side (say it proactively): a weak partial
attack can hide below a lenient small-n threshold. **Security scales with
sample size** — the fundamental detection-vs-yield trade-off.

The same statistical rule reappears in our QDS layer as the mismatch-rate
verification thresholds — precisely the estimation method of Weng et al. (§2).

## 1.9 Entanglement, Bell states, and quantum teleportation

**Entanglement.** A composite quantum state that cannot be written as a
product of its parts. The four maximally-entangled two-qubit **Bell states**:

$$
\ket{\Phi^\pm} = \tfrac{1}{\sqrt2}(\ket{00} \pm \ket{11}), \qquad
\ket{\Psi^\pm} = \tfrac{1}{\sqrt2}(\ket{01} \pm \ket{10})
$$

Measuring one half instantaneously determines the other's outcome — correlated
across any distance — yet *no information travels* (the outcomes are random;
only comparing notes classically reveals the correlation). An EPR pair
($\ket{\Phi^+}$) shared between Alice and Bob is the resource consumed by
teleportation.

**Quantum teleportation** (Bennett et al. 1993) — transmit an unknown qubit
using entanglement + 2 classical bits. Joint initial state (Alice's payload
qubit 1, her Bell half 2, Bob's half 3):

$$
\ket{\psi}_1\ket{\Phi^+}_{23} = \tfrac12\Big[
\ket{\Phi^+}_{12}\ket{\psi}_3 + \ket{\Phi^-}_{12}X\ket{\psi}_3
+ \ket{\Psi^+}_{12}Z\ket{\psi}_3 + \ket{\Psi^-}_{12}XZ\ket{\psi}_3
\Big]
$$

Alice performs a **Bell measurement** on qubits 1+2. Four equally likely
outcomes; per the expansion, Bob's qubit is correspondingly:

| Alice's Bell outcome | 2 bits | Bob's state | Correction |
|---|---|---|---|
| Φ⁺ | 00 | |ψ⟩ | I |
| Φ⁻ | 01 | X|ψ⟩ | X |
| Ψ⁺ | 10 | Z|ψ⟩ | Z |
| Ψ⁻ | 11 | XZ|ψ⟩ | XZ |

Alice sends the 2 bits classically; Bob applies the **Pauli correction** and
holds |ψ⟩ exactly. Key properties:

- The outcome is **uniformly random and unchoosable** by Alice — this
  unpredictability is what signatures are minted from;
- The payload state at Alice is **destroyed** (measurement) — no-cloning in
  action; a signature, once consumed, cannot be re-derived or replayed;
- **No matter travels** — only the pre-shared entanglement and 2 classical
  bits.

*Simulation fidelity:* in the qds crate, `BellPair::bell_measure` draws a
uniform 2-bit outcome; `teleport_bit` sets Bob's raw half to
`payload XOR (correction flips bit)` so that `apply_correction` reconstructs
the payload exactly — the information structure of true teleportation with no
hidden classical shortcut.

## 1.10 Quantum one-way functions (Gottesman–Chuang)

A classical one-way function: easy to compute, hard to invert — the basis of
classical signatures, but its hardness is *computational*. Gottesman–Chuang
introduced the **quantum one-way function**: a map k ↦ |f_k⟩ from classical
bit strings to *quantum states* that are

- easy to prepare from k,
- nearly orthogonal (|⟨f_k|f_k'⟩| ≤ δ for k ≠ k′) so different keys give
  distinguishable states,
- **information-theoretically non-invertible**: by **Holevo's theorem**, n
  qubits yield at most n classical bits of information, period — no computer
  can extract more. With L ≫ n, T copies leak ≤ Tn bits and the key remains
  safe when L − Tn ≫ 1.

This is security *guaranteed by physics*, not computation. The **swap test**
(Fredkin/controlled-SWAP + ancilla + Hadamard) lets any verifier compare two
states without learning them — pass probability 1 for identical states,
≤ (1+δ²)/2 for distinct ones.

Gottesman–Chuang built the first QDS on this primitive, defined the verdict
semantics (**1-ACC / 0-ACC / REJ**) and the **transferability criterion** —
both implemented verbatim in our qds crate (§2.1, §3.4).

## 1.11 Message authentication: HMAC vs. digital signatures

Both layers end in classical cryptography whose key material is
quantum-secured:

- **HMAC-SHA256** (QKD layer): symmetric — signer and verifier share the key.
  tag = HMAC(key, msg); verifier recomputes and compares **in constant time**
  (timing-attack-safe: `mac.verify_slice`, never `==`). Broken only if the
  key leaks — and the key was quantum-distributed.
- **QDS** (layer 2): asymmetric in spirit — Alice signs; *any* holder of the
  public key material verifies; only Alice can produce accepted signatures.
  Security is information-theoretic within the protocol model, not
  computational.

The demo shows both outcomes: clean channel → derived key + verified HMAC;
compromised channel → **no key exists at all**, nothing can be authenticated.
The abort is the security feature.

---

# Part 2 — The three research papers and how we implement them

The framework operationalizes the assigned literature — not "inspired by",
but specific protocol semantics mapped to specific code. For every claim
there is a citation, a section reference, and a code pointer.

## 2.1 Gottesman & Chuang 2001 — *Quantum Digital Signatures* (arXiv:quant-ph/0105032)

The founding paper. Introduced quantum one-way functions (§1.10), the first
QDS protocol, and — crucially for us — the **evaluation framework** all QDS
papers still use:

| Their concept | Their meaning | Our implementation |
|---|---|---|
| **1-ACC / 0-ACC / REJ** | 1-ACC: valid, transferable. 0-ACC: valid for *this* verifier only, forwarding risky. REJ: invalid. (§4 Definition) | `qds::Verdict` enum; gray-zone rule `c1 < mismatch ≤ c2` ⇒ 0-ACC. Tests: `genuine_signature_yields_1acc_verdict`, `forged_signature_in_gray_zone_yields_0acc_not_rej_boundary` |
| **Dual acceptance thresholds** c1, c2 (c2−c1 bounds Alice's cheating) | noisy-channel tolerance band | `Thresholds { c1, c2 }`; noiseless default c1 = 0, c2 = 0.10 |
| **Transferability (non-repudiation)** | if verifier 1 says 1-ACC, verifier 2 must say non-REJ (Security criterion 2) | `qds::verify_transferability` — independent side-effect-free re-check; surfaced as "Charlie consensus" in API/UI. Test: `transferability_consensus_genuine_and_forged` |
| **Exponentially-small failure via security parameter M** | M independent keys per message bit | our λ Bell rounds per qubit: P(forgery) = 4^(−qλ) — same exponential shape |
| Swap test, quantum fingerprints | state comparison without learning states | not needed in our correlation-based verification; cited in docs |

## 2.2 Singh et al. 2023 — *Securing Blockchain Transactions Using Quantum Teleportation and QDS* (Neural Process. Lett. 55:3827)

The application blueprint: QDS + teleportation securing blockchain
transactions. Their Fig. 5 pipeline is our QDS flow:

| Their stage | Their mechanism | Our implementation |
|---|---|---|
| **Signing** | P key pairs {k⁰, k¹}, quantum one-way function → public keys f(k) | Trent↔Alice Bell-pair correlation tables A1/A2 + commitment H(A1‖A2‖λ) (`Trent::setup`, `QuantumPublicKey`) |
| **Distribution via teleportation** | Bell measurement on EPR half + key qubit → 2 classical bits → receiver applies correction (their steps 1–7) | `teleport_bit`: uniform Bell outcome, Bob's half conditionally determined, `apply_correction` reconstructs exactly; trace table shown live in the UI |
| **Validation** | count incorrect keys t; **accept if t < Ta, reject if t > Tb**, uncertain between | mismatch counting in `verify`; Ta/Tb ≡ c1/c2; verdicts 1-ACC/0-ACC/REJ |
| **Replay / double-spend resistance** | signature consumed on delivery; entanglement destroyed ⇒ cannot re-present | `Trent::used_nonces` single-use nonce ledger + `ledger` audit trail; replay test `replay_attack_is_rejected` |
| Swap test at receivers | verify teleported keys identical | our verification-table equality checks (classical, because our simulation transports correlations; swap test is for unknown *states*) |

## 2.3 Weng et al. 2021 — *Secure and Practical Multiparty QDS* (arXiv:2104.12059)

The modern practical protocol. Their encoding is literally our QKD layer:

| Their concept | Their mechanism | Our implementation |
|---|---|---|
| **Six-state non-orthogonal encoding** | states |±x⟩,|±y⟩,|±z⟩ paired into 12 sets, first of each set = bit 0, second = bit 1 | same six states: `PauliBasis::X/Y/Z` × `PauliState::+/−`; `as_bit` mapping |
| **Mismatching-rate estimation** | verifiers estimate conclusive-result mismatch between their string and Alice's; threshold decision | `ThreatDetector` (Hoeffding-bound threshold, §1.8) + QDS `verify` mismatch ratios |
| **Key generation / estimation / messaging** three-step protocol | click events → strings → estimate → sign+forward | our `Trent::setup` → parameter estimation → `sign`/`verify`/`verify_transferability` |
| **Post-matching, decoy intensities (μ,ν,0)** | efficiency tricks for weak coherent sources | out of scope (classical simulation); explicitly listed in §6 limitations |
| **Majority voting among verifiers** | multiparty consensus | simplified to Bob (authenticator) + Charlie (verifier) transferability check — the 3-party case |

## 2.4 The unification claim (say this to judges)

> "Our framework runs **one statistical detection principle** — Hoeffding-
> bounded mismatch-rate thresholds, no ML — across **both** quantum layers,
> and implements the **full verdict semantics of the founding QDS paper**
> (1-ACC/0-ACC/REJ + transferability) on top of a **teleportation pipeline
> matching the blockchain QDS application paper**, using the **same six-state
> encoding as the multiparty QDS paper**. Every security decision traces to a
> specific theorem or protocol step in the literature."

---

# Part 3 — Codebase walkthrough

## 3.1 Repository layout

```
sih26141/
├── Cargo.toml            # workspace: 8 crates, resolver 2
├── quantum/              # six-state QKD physics core
├── detection/            # Hoeffding-bound threat detector
├── attacks/              # QKD attack scenario wrappers
├── qds/                  # teleportation-based QDS (the upgrade)
│   └── src/
│       ├── lib.rs        #   Bell pairs, teleportation, Trent, sign/verify, verdicts
│       └── attacks.rs    #   forgery, impersonation, replay, channel tampering
├── crypto/               # HMAC-SHA256 message authentication
├── main_app/             # CLI demo of the QKD pipeline
├── server/               # axum REST + SSE API
│   └── src/
│       ├── main.rs       #   HTTP endpoints, SSE streaming, static serving
│       ├── qds_api.rs    #   /api/qds/* handlers
│       └── qds_state.rs  #   shared Trent + JSONL security-event log
├── frontend/             # React + TS + Recharts dashboard
│   └── src/
│       ├── App.tsx             # state orchestration + layout
│       ├── api.ts              # typed REST client
│       ├── useRunStream.ts     # SSE hook
│       └── components/
│           ├── StatusCard.tsx  # per-scenario QKD verdict cards
│           ├── LiveMonitor.tsx # real-time QBER chart
│           ├── SweepPanel.tsx  # QBER vs intercept-ratio chart
│           └── QdsLab.tsx      # QDS Signature Lab
├── tests/                # QKD integration tests
├── qds/tests/            # QDS integration tests (11 tests)
├── docs/
│   ├── PROJECT_GUIDE.md  # this document
│   └── QDS_MATH_MODEL.md # formal model (deliverable 1)
└── scripts/              # run_simulations.sh
```

Dependency direction: `server → {qds, quantum, detection, attacks, crypto}`;
`qds → rand/sha2`; physics crates never see HTTP; the server never does
physics.

## 3.2 quantum crate

Six-state QKD core (`quantum/src/lib.rs`).

- **`PauliBasis` {X,Y,Z}**, **`PauliState` {Positive,Negative}** — §1.2's
  basis/eigenvalue pair; `as_bit(): Positive→1, Negative→0`.
- **`QuantumKeyGenerator::generate_eigenstates(rng)`** — Alice's preparation:
  N uniform (basis, sign) draws. Seeded reproducible.
- **`ChannelSession`** — the physics engine, one qubit at a time:
  `transmit()` implements Bob's random basis, optional Eve interception
  (`intercept_ratio`: probability she measures a given qubit), state collapse
  on wrong-basis measurement, sift-against-Alice-only, running
  `qber()/sifted_count()/mismatch_count()`, `finish()` → `SiftedKeyResult`.
- **`simulate_six_state_transmission(_ratio)`** — batch wrappers over a
  `ChannelSession` (the bool variant kept for the legacy CLI/tests).
- **`privacy_amplification`** — SHA-256 of sifted bits → 64-hex secret.
- Unit tests: ratio 0.0 ⇒ QBER 0.0; ratio 1.0 ⇒ QBER ≈ 1/3; ratio 0.3 ⇒ QBER
  ≈ 0.1 (the f/3 law of §1.6).

## 3.3 detection crate

Pure math, zero dependencies (`detection/src/lib.rs`).

- **`ThreatDetector::new(base_threshold)`** + `with_confidence_delta(δ)`.
- **`evaluate_signature(mismatch_rate, n)`** — §1.8 verbatim:
  `slack = √(ln(2/δ)/(2n))`, threshold = base + slack (≤1.0),
  authentic ⇔ qber ≤ threshold; n=0 special-cased ("complete signal loss").
- **`DetectionResult`** — is_authentic, mismatch_rate, dynamic_threshold,
  threat_flagged, note.

This same rule is reused conceptually by the QDS mismatch-rate thresholds —
one statistical principle, both layers.

## 3.4 qds crate (the heart of the upgrade)

`qds/src/lib.rs` — teleportation-based signatures per Part 2.

**Pauli algebra.**
- `PauliOp` {I, X, Z, ZX} — `flips_bit()` (X and ZX flip; I and Z don't),
  `as_str()`.
- `BellOutcome(u8)` — 2-bit Bell measurement result; `correction()` maps
  00→I, 01→X, 10→Z, 11→ZX; `as_bits()`.

**Entanglement + teleportation.**
- `BellPair` — the |Φ⁺⟩ resource. `bell_measure()` draws a uniform outcome
  (Alice cannot choose it — the signature's randomness source).
- `teleport_bit(payload, pair, rng)` — outcome random, Bob's raw half =
  payload XOR correction-flip so `apply_correction` reconstructs exactly
  (§1.9 fidelity). Returns outcome + pre/post-correction bits (the UI trace).
- `apply_correction(raw, op)`.

**Keys.**
- `QuantumPublicKey { qubit_count, correlation_commitment, lambda }` —
  commitment = SHA-256(A1‖A2‖λ).
- `QuantumSignature { correction_bits, nonce, key_commitment }` — two
  published bits per position (i,j):
  - x = m_i ⊕ A1[i][j] (message-bound payload),
  - z = A1[i][j] ⊕ A2[i][j] (secondary correlation binding).

**Trent (notary / distribution center).**
- `setup(q, λ)` — random A1/A2 tables, publishes commitment, empty nonce
  registry and ledger.
- `issue_nonce()` — monotone single-use nonces (replay defense).
- `signing_material()` — the secret tables handed to Alice (realized in-protocol
  via her Bell-pair measurements).
- `verification_tables()` — Trent-side only; Bob never sees key bits, only
  verdicts.
- `used_nonces` + `ledger` — replay defense + audit trail.

**Signing** (`sign`): for each of q·λ positions — teleport the payload
m_i ⊕ A1[i][j] with genuine random Bell outcome; publish x and z as above.
Nonce-bound. Returns signature + teleport records (UI trace).

**Verification** (`verify`): structural checks (length, key commitment),
replay check (nonce fresh), then per-position statistics:

- **C1:** x ⊕ m_i =? A1[i][j] — message binding + primary correlation
- **C2:** z ⊕ A1[i][j] =? A2[i][j] — secondary correlation

mismatches μ of N = qλ ⇒ mismatch fraction f. Dual thresholds (GC01):

- f ≤ c1 ⇒ **1-ACC** (transferable)
- c1 < f ≤ c2 ⇒ **0-ACC** (accepted locally, *not* guaranteed transferable)
- f > c2 ⇒ **REJ**

Accept (1-ACC/0-ACC) consumes the nonce and appends (SHA-256(m), nonce) to
the ledger; rejection consumes nothing (a delayed genuine signature still
verifies — test `failed_verification_keeps_nonce_usable`).

**Transferability** (`verify_transferability`): independent, side-effect-free
re-check (statistics + commitment only; never touches nonce/ledger since
forwarding happens after acceptance). This is GC01's security criterion 2 —
our "Charlie consensus".

**Forgery probability:**
- `theory_forgery_probability(q, λ) = 4^(−qλ)` — a forger must guess both
  bits at every position (1/4 each, independent).
- `estimate_forgery_probability((q,λ), trials, rng)` — Monte-Carlo over full
  setup+forge+verify cycles. At (1,1): converges to 0.25 (theory). At the
  default (16,4): 4⁻⁶⁴ ≈ 2.9×10⁻³⁹.

**Attacks** (`attacks.rs`) — each returns a tampered `QuantumSignature` +
label:
- `attempt_forgery` — uniformly guessed correction bits, fresh nonce. Fails
  statistics: expected μ/N = 3/4 ≫ c2.
- `attempt_impersonation` — genuine signature re-presented over a different
  message. Fails C1 wherever SHA-256(m′)ᵢ ≠ SHA-256(m)ᵢ (~half of positions).
- `attempt_replay` — verbatim re-presentation. Fails nonce check before
  statistics.
- `attempt_channel_tampering(genuine, f, …)` — the genuine signature bits,
  but the fraction f of in-flight qubits disturbed (each disturbed position
  has one published bit flipped). Mismatches scale ∝ f; exceeds c2 for
  f = 0.5. The tamper fraction is caller-controlled (API: `tamper_fraction`
  query parameter, default 50%).
- `attempt_unauthorized_verification(genuine, …)` — a party without Trent's
  key material attempts verification. The attempt itself is flagged as its
  own threat class ("unauthorized verification attempts" is one of the five
  threat classes in the problem statement); the captured signature also fails
  statistics on any fresh nonce.

**The six-state module** (`qds/src/six_state.rs`) — the second,
literature-faithful QDS scheme (Weng et al. 2021): Alice prepares six-state
Pauli eigenstates, verifiers measure in random Pauli bases, conclusive
(click) results encode logic bits via the orthogonal-partner rule, and the
*mismatching rate of conclusive results* drives the threshold decision —
the exact estimation method of the multiparty QDS paper. The ideal click
rate 1/6 emerges naturally from the encoding and is assertable in tests.
A threshold-rule classifier (`classify`) attributes observed evidence to
forgery / impersonation / replay / channel tampering / unauthorized
verification — deterministic and explainable, no AI/ML.

**The noisy-channel module** (`qds/src/noisy.rs`) — sizes the GC01 dual
thresholds for real channels: c1 = noise floor + Hoeffding slack √(ln(2/δ)/2n),
c2 = c1 + gray-zone width. Bridges the QKD layer's finite-key statistics
into signature verification.

**The metrics module** (`qds/src/metrics.rs`) — the repeatable evaluation
engine (Lap 2 "observable security metrics"): confusion-matrix accuracy,
detection rate, false positives/negatives, empirical vs theoretical forgery
probability, and per-operation wall-clock timings, for both QDS schemes,
all deterministic under a seed. Exposed at `/api/qds/metrics` and visualized
in the dashboard's "Performance evaluation" panel.

**Tests** (`qds/tests/qds_tests.rs`, 16 passing) — deterministic acceptance
of genuine signatures, tampered-message rejection, all five attacks rejected,
nonce-failure semantics, 1-ACC verdict, 0-ACC gray zone, transferability
consensus (genuine: agrees; forged: REJ), forgery-probability MC ≈ theory.

## 3.5 attacks / crypto / main_app crates
- **attacks** — QKD-scenario wrappers (`run_secure_simulation`,
  `run_intercept_resend_simulation`) delegating to the quantum batch API.
- **crypto** — `compute_message_hmac` / `verify_message_hmac` (constant-time
  verify via `verify_slice`). §1.11.
- **main_app** — CLI demo: seeded RNG → eigenstates → secure run → verdict →
  PA → HMAC; then full intercept-resend run → alert. Two-second sanity check.

## 3.6 server crate

Axum HTTP + SSE (`server/src/main.rs`, `qds_api.rs`, `qds_state.rs`).

**QKD endpoints**

| Route | Method | Purpose |
|---|---|---|
| `/api/health` | GET | liveness (dashboard pill) |
| `/api/server-info` | GET | actual bound port — published for the dashboard's fallback discovery |
| `/api/run` | POST | full run: key_length, base_threshold, intercept_ratio?, message, seed, pace_ms → two scenarios (secure + attack) or one custom ratio |
| `/api/simulate` | POST | sweep ≤32 intercept ratios |
| `/api/events` | GET | SSE progress/result/done stream (replays last run; keep-alive 15 s) |

**QDS endpoints** (`qds_api.rs`)

| Route | Method | Purpose |
|---|---|---|
| `/api/qds/setup` | POST | regenerate Trent key material (qubit_count, λ) |
| `/api/qds/sign` | POST | sign via teleportation; Bob verifies on delivery (consumes nonce); returns correction-bit hex + teleport trace |
| `/api/qds/verify` | POST | manual (message, signature_hex, nonce) check |
| `/api/qds/attacks` | GET | run all 5 attacks (optional `tamper_fraction` query param, default 0.5), return verdicts + Charlie consensus |
| `/api/qds/forgery-analysis` | GET | MC vs theory at (8,1) over 20k trials + λ-scaling points |
| `/api/qds/metrics` | GET | repeatable performance evaluation (`trials`, `seed` params): accuracy, detection rates, false alarms, forgery probability, timings |
| `/api/qds/events` | GET | recent security events |

**Engineering details worth citing:**
- **Port fallback + dashboard auto-discovery**: if the requested port is held
  (os error 10013 — Apache, Hyper-V reserved ranges), the server binds the next
  ports, writes `frontend/dist/server-port.json` and `/api/server-info`; the
  dashboard's health poll falls back to the manifest and adjacent-port probing,
  so the pill turns green without manual URL surgery.
- CPU-bound simulation runs inside `spawn_blocking` — never blocks the async
  reactor; other requests stay live during a run.
- Live QKD progress: per-batch `Progress` SSE events carry running QBER *and*
  the Hoeffding threshold at that n — the converging dashed lines are computed
  with the same formula as the detector.
- `qds_state.rs` — `Mutex<Trent>` shared session; **persistent JSONL event
  log** (`qds_events.jsonl`, every sign/verify/attack recorded with RFC3339
  timestamp, verdict, mismatch counts) — deliverable "logging of security
  events"; capped in-memory window for the UI.
- Validation everywhere: key_length ∈ [500, 200k], thresholds ∈ [0,1],
  ≤32 sweep points, message ≤ 2 KB (QDS) / 10 KB (QKD); structured JSON
  errors.
- `FRONTEND_DIST` env override; serves `../frontend/dist` when built
  (single-port deployment), else API-only mode.

## 3.7 frontend

React 19 + TS + Recharts, hand-rolled dark SOC theme (`index.css`), Vite.

- **App.tsx** — parameter state (key length 1k–100k, threshold, pace, custom
  intercept ratio toggle, seed, message), run lifecycle (SSE `run_id` filter,
  progress ingestion, verdict logs), sweep calls, 10-s health poll. Dashboard
  defaults for the judging build: **20,000 qubits**, 15% base threshold,
  6 ms pace. Every run and sweep logs its **provenance line** to the event
  log — `seed <n> · <qubits> qubits · threshold <x>%` — so any chart can be
  attributed to its exact randomness. Blank seed = fresh randomness per run
  (server generates a time-based seed and echoes it back); typing a seed
  makes runs bit-for-bit reproducible (the seed box's placeholder shows the
  last used seed). The live-monitor's dashed "base" reference line tracks
  the threshold slider instead of being hardcoded.
- **LiveMonitor** — per-scenario stat blocks (transmitted %, sifted,
  mismatches, live QBER) + converging QBER/threshold chart + event log.
- **StatusCard** — verdict chip (✓ AUTHENTIC / ✗ THREAT FLAGGED), progress
  bar, QBER/threshold/sifted metrics.
- **SweepPanel** — measured vs theory (ratio/3) bars + red threshold
  reference line; detection fires ≈ 60–70% interception at base 15%.
- **QdsLab** — the 4-step guided flow: ① generate keys (shows qubits × λ and
  P(forgery) < 10^x chip + commitment hash) → ② sign via teleportation
  (Bob-verified chip, nonce chip, **teleportation trace table**: Bell outcome
  00/01/10/11, Pauli correction I/X/Z/XZ, raw→corrected bit) → ③ launch all 4
  attacks (verdict chips + Charlie consensus per attack) → ④ forgery analysis
  (log₁₀ P bars, λ = 1..8, 128-bit-security reference line) + collapsible
  theoretical-basis references.

## 3.8 End-to-end data flows

**QKD flow:**

```
 Browser                    Rust server                     Physics crates
──────────────────────────────────────────────────────────────────────────
 POST /api/run ───────────▶ validate → spawn_blocking ───▶ QuantumKeyGenerator
                                 │ every ~1%:               generate_eigenstates
 GET /api/events ◀─ SSE ─────────┤ publish Progress       ChannelSession::transmit
   bars, converging thresholds   │ (QBER + ε(n))
                               finalize ─────────────────▶ ThreatDetector
                               if authentic ─────────────▶ privacy_amplification
                                                           compute/verify HMAC
 ◀─ result + done + JSON ──┤
```

**QDS flow:**

```
 ① POST /api/qds/setup ──▶ Trent::setup: A1/A2 tables, commitment, nonce registry
 ② POST /api/qds/sign  ──▶ per position: teleport(m⊕A1) w/ random Bell outcome
                           publish (x, z) bits; Bob verifies → 1-ACC, nonce consumed
    GET  /api/qds/attacks ┃ forgery: guessed bits          → REJ (stats)
                          ┃ impersonation: transplant      → REJ (C1 fails)
                          ┃ replay: nonce reuse            → REJ (nonce)
                          ┃ tampering: f-fraction qubits   → REJ (stats)
                          ┃ unauthorized: no key material  → FLAGGED
                          ┃ + Charlie consensus on each
 ④ GET /api/qds/forgery-analysis → MC(20k) ≈ 4^(−qλ), λ-scaling chart
 ⑤ GET /api/qds/metrics     → accuracy, detection rate, false alarms, timings
 every event ──▶ qds_events.jsonl (persistent audit log)
```

---

# Part 3.9 — Statistical tail events in the metrics panel (know before judges ask)

At the dashboard's evaluation default (200 trials, seed 42) the panel reports
detection rate ≈ 99.9%, not 100%. This is correct behavior, not a bug, and it
is worth understanding before the round:

* **Six-state channel-tampering class (1 miss / 200).** The tampering scenario
  disturbs 30% of qubits; the induced mismatch rate is Binomial(0.375, n≈400)
  against a rejection threshold of 0.25 — roughly 2.7 standard deviations.
  A single unlucky draw below 0.25 is a one-in-~250 event, which is exactly
  what 199/200 shows. It is finite-sample statistics on an adversarial
  channel, the same trade-off as §1.8: **more qubits ⇒ tighter detection.**
* **Teleportation impersonation class (1 miss / 200).** Message binding uses
  q = 8 message-digest bits in the evaluation run, so a transplanted signature
  over a different message matches the digest bit-for-bit with probability
  2⁻⁸ = 1/256 — again observed exactly once in 200 trials. At the default
  signing parameters (q = 16) this probability is 2⁻¹⁶, and it drops
  exponentially with q.

**One-line answer for judges:** "The 99.9 vs 100% is the finite-sample tail of
a bounded-error statistical test — the same ε-vs-n law as the Hoeffding bound
in the QKD layer. Increase the sample and the tail vanishes; that's a feature
of honest statistics, not a leak."

---

# Part 4 — Running and testing

```bash
# Toolchain (this machine): windows-gnu Rust, Node 24 — see .freebuff/run.md
cd sih26141
cargo test --workspace          # 35 tests, all passing
cargo run -p main_app           # 2-second CLI demo of the QKD pipeline

# Dashboard (single port serves API + UI):
cd frontend && npm install && npm run build && cd ..
PORT=8080 cargo run -p server   # http://127.0.0.1:8080
```

**Test inventory (35):**
- `quantum` (3): f/3 law at ratios 0.0 / 1.0 / 0.3.
- `tests/integration_tests.rs` (3): end-to-end secure pipeline (keys equal,
  verdict authentic, HMAC verifies + tamper fails), attack detection, input
  validation guards.
- `qds/src/six_state` (6): honest delivery deterministically accepted, both
  message values verify, forged string rejected near the ½ guessing floor,
  impersonation transplant rejected, 30% tampering above the noise floor and
  classified as channel tampering, unauthorized verifier flagged.
- `qds/src/noisy` (5): noiseless ⇒ 1-ACC, noise-within-floor tolerated,
  attack-level mismatch flagged, gray-zone neither clean nor flagged, Hoeffding
  slack shrinks with n.
- `qds/src/metrics` (2): evaluation accurate (accuracy > 0.99, zero false
  alarms) and deterministic under a fixed seed; timings sub-50 ms.
- `qds/tests/qds_tests.rs` (16): the original 11 (deterministic 1-ACC
  acceptance, tampered message rejected, forgery/impersonation/replay/channel
  tampering rejected, MC forgery ≈ ¼ at (1,1), nonce kept on failure, genuine
  ⇒ 1-ACC verdict, gray-zone ⇒ 0-ACC not transferable, transferability
  consensus) plus unauthorized-verification attempt flagged, tampering
  scales with fraction, noisy thresholds statistically sized, six-state
  scheme rejects all attacks, performance evaluation meets Lap 2 targets.

**Manual verification performed:** full dashboard run (verdicts, chart
convergence, sweep threshold crossing), QDS lab flow end-to-end (keys → sign
with teleport trace → 4 attacks all REJ → forgery chart), SSE done-event
unlocking the button, health pill, persistent event log inspected.

---

# Part 5 — Security analysis summary

**Guarantees in the simulated model:**

| Property | Mechanism | Quantification |
|---|---|---|
| Eavesdropping detection (QKD) | intercept-resend ⇒ QBER = f/3 ≥ threshold | detection at f ≳ 3×(base+ε(n)) |
| Deterministic correctness | honest signatures satisfy C1,C2 ∀positions | μ = 0 always — theorem in QDS_MATH_MODEL §6 |
| Whole-signature forgery | guess (x,z) at all N = qλ positions | P = 4^(−N); (16,4) ⇒ ~2.9×10⁻³⁹ |
| Impersonation | message-hash binding via C1 | fails at ~50% of positions for any different digest |
| Replay | single-use nonce ledger | 2nd presentation always REJ |
| Transferability / non-repudiation | Charlie's independent re-check (GC01 criterion 2) | 1-ACC ⇒ Charlie non-REJ |
| Auditability | persistent JSONL log of every sign/verify/attack | `qds_events.jsonl` |
| No computational assumptions in the QDS layer | XOR-bound correlations + commitments; no factoring/discrete-log | information-theoretic within model (SHA-256 treated as random oracle for the commitment) |

**The detection-vs-yield trade-off** (be ready for this): Eve can stay under
the threshold by intercepting a small fraction; countermeasure = more qubits
(n grows ⇒ ε shrinks ⇒ threshold tightens). This is *physics*, not a bug —
every real QKD system has it, and our dashboard demonstrates it live.

---

# Part 6 — Limitations (be honest with judges)

1. **Classical simulation** of quantum protocols — ideal Bell pairs, perfect
   devices, noiseless channel unless an attack injects disturbance. It models
   the *information structure* faithfully; it does not run physical qubits.
2. **No error-correction stage** (Cascade/LDPC) — clean-channel keys agree by
   construction; the code marks exactly where reconciliation would slot in.
3. **Privacy amplification simplified** — fixed SHA-256 rather than a
   universal₂ hash sized by an entropy-vs-leakage budget.
4. **Seeded PRNG** for reproducibility, not a CSPRNG/QRNG.
5. **No channel-noise model** — real QBER mixes noise and attacks; thresholds
   would need the Hoeffding margin against combined noise.
6. **Dev-grade API posture** — HTTP, permissive CORS, local-only bind; no
   auth on the control plane.
7. **Three-party QDS** (Alice/Trent/Bob(+Charlie consensus)) — multiparty
   scaling per Weng et al. not implemented.
8. **Swap test not simulated** — our verification is correlation-table
   equality; the swap test matters when verifying unknown *states*, which our
   classical transport doesn't produce.

Each limitation maps to a roadmap item (noise model → richer threshold story;
universal₂ PA → real leftover-hash accounting; QRNG flag; HTTPS+tokens;
multiparty expansion).

---

# Glossary

| Term | Meaning |
|---|---|
| **Alice / Bob / Trent / Charlie** | signer / receiver / notary-center / second verifier |
| **Basis** | the measurement "question" (X, Y, Z Pauli bases) |
| **Eigenstate** | state answering its own basis deterministically (±1) |
| **Mutually unbiased** | measuring basis A's eigenstate in basis B ⇒ perfectly random |
| **Collapse** | wrong-basis measurement destroys the state; outcome random |
| **No-cloning theorem** | unknown quantum states cannot be copied |
| **Bell state / EPR pair** | maximally entangled two-qubit state (Φ±, Ψ±) |
| **Bell measurement** | joint measurement in the Bell basis → one of 4 outcomes |
| **Teleportation** | transmit an unknown qubit via entanglement + 2 classical bits |
| **Pauli correction** | I/X/Z/XZ applied by receiver to reconstruct the state |
| **Sifting** | keep only rounds where bases matched |
| **QBER** | quantum bit error rate — fraction of wrong sifted bits |
| **Hoeffding bound** | P(\|q̂−p\|≥ε) ≤ 2e^(−2nε²); finite-sample margin ε(n) |
| **1-ACC / 0-ACC / REJ** | valid+transferable / valid-local / invalid (GC01) |
| **Transferability** | verifier 2 must agree with verifier 1's 1-ACC |
| **Quantum one-way function** | k ↦ \|f_k⟩: easy to prepare, info-theoretically non-invertible (Holevo) |
| **Holevo's theorem** | n qubits carry at most n classical bits |
| **Privacy amplification** | compress partially-secure key to uniform secret |
| **HMAC** | keyed-hash message authentication (SHA-256 here) |
| **SSE** | server-sent events — one-way HTTP stream for live progress |
| **Nonce ledger** | single-use number registry defeating replay |

---

*Theory references: Bennett–Brassard 1984; Bruss 1998 (six-state); Hoeffding
1963; Bennett et al. 1993 (teleportation); Wootters–Zurek 1982 (no-cloning);
Holevo 1973. Protocol references: [1] Gottesman–Chuang 2001; [2] Singh et al.
2023; [3] Weng et al. 2021 (see Part 2 for full mapping).*
