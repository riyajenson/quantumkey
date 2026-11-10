# QuantumKey — Project Handoff and Agent Operating Guide

> **Purpose:** Establish a reliable working baseline for any contributor or coding agent entering this repository. This file is an operating guide, not evidence that any feature exists. The actual repository, code, documentation, Git state, and hardware artifacts are authoritative.
>
> **Current state (2026-11-06):** The repository was audited and a prototype now exists on the `phase-3` branch (`quantumkey/` package, `tests/`). Phase status is tracked in `docs/MILESTONE_ACCEPTANCE.md`, and candidate contributions and limits in `docs/RESEARCH_NOTES.md`. Sections 4–10 below remain the operating principles; verify any specific claim against the code.

## 1. Project identity

QuantumKey is intended to explore post-quantum authentication using NIST ML-DSA (formerly CRYSTALS-Dilithium) digital signatures. The long-term vision is a user-controlled authenticator whose private signing key remains with the authenticator, with a software-first prototype and a possible hardware-backed token later.

The project should distinguish clearly between:

- **What is implemented:** only what the current source tree and reproducible evidence demonstrate.
- **What is specified:** documented intended behavior that may not yet exist in code.
- **What is experimental:** a hypothesis or prototype awaiting measurement or security review.
- **What is future work:** an idea, roadmap item, or unvalidated research direction.

Never describe planned functionality as shipped or verified.

## 2. Non-negotiable working rules

These rules apply to every task unless the user explicitly changes them:

1. **No pushing.** The user will push manually. Never push commits, branches, tags, or other refs to a remote. Do not publish releases or open PRs.
2. **Run tests at all stages.** Run the test suite (`python -m pytest -q`) at the start of a task to record the baseline, after each change, and before every commit; report the exact result. When server or database code changes, also run the server tests on PostgreSQL (see the Docker section of `README.md`). Never claim something works without a passing run, and never commit on a failing suite without saying so. Benchmarks, dependency installs and other heavier tooling still need the user's approval.
3. **No subagents until explicitly authorized.** Do not spawn, delegate to, or coordinate parallel agents.
4. **Micro-commit everywhere.** When commits are authorized, make small, focused, coherent local commits. Inspect the diff and stage only the intended files. Do not combine unrelated changes.
5. **No Claude mention on micro-commit.** Commit messages must not mention Claude, AI tools, agents, or tool-generated attribution. Use ordinary project-focused messages, for example `docs: define authenticator trust boundaries`.

Additional safeguards:

- Begin with `git status` and preserve all user changes. Never assume a dirty tree is disposable.
- Do not use destructive cleanup, hard resets, force operations, amend, rebase, or branch deletion unless the user explicitly authorizes the exact operation.
- Do not create branches, tags, issues, PRs, releases, files, tests, or implementation artifacts during an initial audit. For any later artifact creation, stay within the user's explicitly approved scope.
- Do not install dependencies, change lockfiles, update toolchains, or add services without approval.
- Do not expose secrets. Avoid printing `.env` contents, tokens, private keys, credential databases, or signing material. Report variable names and whether values are present, not their values.
- Ask before changing the project's phase, architecture, cryptographic algorithm, API contract, or security assumptions.
- Report what was inspected, what was not inspected, and what remains unverified.

## 3. First task: read-only repository and directory audit

The first task after entering the actual project is an audit, not implementation.

### 3.1 Establish the real project location

- Confirm the current working directory and repository root.
- If the supplied directory is not a Git repository, report that fact and inspect only the directory the user intended.
- Do not guess a project path or silently switch to another clone/worktree.

### 3.2 Inspect the repository

Read the relevant contents of:

- Root-level files, including README, contribution instructions, license, manifests, lockfiles, and hidden project configuration.
- All repository-specific agent instructions (`AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `skill.md`, `SKILL.md`, and nested equivalents), while respecting this guide's stricter user rules.
- `docs/`, architecture notes, decision records, threat models, API specifications, and milestone trackers.
- Backend, client, authenticator, vault, cryptography, browser integration, hardware/firmware, benchmarks, deployment, and infrastructure directories if present.
- CI workflows and scripts as text only. Do not execute them.

Map imports, entry points, interfaces, data models, routes, cryptographic call paths, persistence, configuration, and deployment wiring. Search for TODO/FIXME markers, stubs, placeholder responses, duplicated logic, dead paths, and mismatches between docs and source. Inspect generated or vendored directories selectively; do not mistake them for authored implementation.

### 3.3 Inspect Git without changing it

Read and report:

- Current branch and HEAD commit.
- Working-tree status, including staged, unstaged, and untracked files.
- Recent commit history and relevant branch names.
- Configured remotes (names and URLs may be summarized; do not contact or push to them).
- Existing tags and repository state relevant to the task.

Do not fetch, pull, checkout, switch, stash, reset, clean, amend, rebase, or push during the audit.

### 3.4 Run the tests; do not mutate the project

During the initial audit, run the test suite to establish a baseline (rule 2). Do not run commands that mutate files or the environment: formatters, migrations against real databases, package installation, code generation, or application startup. Static commands that list files, inspect Git metadata, or read source are acceptable.

### 3.5 Required audit report

Before proposing implementation, return a concise but complete report containing:

1. Actual repository root and current branch/commit.
2. Git working-tree status and any pre-existing user changes.
3. A useful directory tree and a map of the real architecture.
4. What is implemented, partially implemented, specified only, stubbed, missing, or unclear.
5. The actual registration/login and signing flows, if present.
6. Cryptographic library and algorithm usage, including version/configuration evidence.
7. Private-key generation, storage, loading, backup, recovery, and deletion behavior.
8. API endpoints and request/response contracts actually present.
9. Browser/client/authenticator integration status.
10. Hardware/firmware/transport status, if any.
11. Dependency, packaging, deployment, and CI state (inspection only).
12. Documentation status, including the eight Phase 1 documents below.
13. Security concerns, design gaps, and unsupported claims.
14. Blockers, assumptions requiring decisions, and evidence gaps.
15. Prioritized remaining work with dependencies and acceptance criteria.
16. Exact next files or sections proposed for change — but do not change them yet.

Clearly label any item not inspected as **not inspected** and any claim without evidence as **unverified**. Wait for the user's approval before making changes.

## 4. Product and compatibility boundaries

### 4.1 Cryptographic terminology

- ML-DSA is a **digital signature** scheme standardized by NIST in FIPS 204. It is not an encryption or key-encapsulation algorithm.
- A signature proves that the holder of a corresponding private key signed a message, subject to correct key management and protocol verification. It does not by itself establish user identity, user intent, website authenticity, or session security.
- Do not call an implementation “quantum-proof.” Prefer “post-quantum cryptographic algorithm” or “designed to resist known quantum attacks under its security assumptions.”
- Do not imply that present-day quantum computers can break all current authentication systems. The motivation includes the long-term risk to vulnerable public-key cryptography and the need to migrate before cryptographically relevant quantum capabilities exist.

### 4.2 WebAuthn boundary

Standard WebAuthn does not automatically accept arbitrary ML-DSA credentials. Compatibility requires support across the relevant browser/client, authenticator protocol, algorithm negotiation, relying party, and credential formats. Unless demonstrated end-to-end, describe QuantumKey as a **custom compatible authentication protocol** or **WebAuthn-inspired research prototype**, not as a drop-in authenticator for arbitrary websites or services.

Never claim compatibility with Google, GitHub, or any other relying party unless an actual supported integration has been implemented and verified with permission.

### 4.3 Product stages

The likely progression is:

1. Specification and threat-model phase.
2. Software authenticator prototype using a vetted ML-DSA implementation.
3. Developer/relying-party integration and usable client workflow.
4. MCU-based hardware prototype with a signing boundary.
5. Hardening and, if justified, hardware acceleration or FPGA research.

The repository audit must determine the current stage. Do not assume this roadmap is the approved current milestone.

## 5. Intended architecture — verify before treating as current

The following is design context, not a claim about existing code:

- Desktop authenticator first; mobile may be a later client.
- Local encrypted SQLite vault for software credentials.
- ML-DSA operations through a maintained implementation such as liboqs / an appropriate language binding, subject to version and API verification.
- A backend may use FastAPI, PostgreSQL, SQLAlchemy, and Alembic if that is what the repository actually adopts.
- Registration and login may use challenge-response endpoints such as `/auth/register/start`, `/auth/register/complete`, `/auth/login/start`, and `/auth/login/complete`.
- Server stores public keys and credential metadata; the private key must never be sent to the server.
- A `SigningBackend`-style abstraction could separate software and hardware signing implementations.

Do not introduce this architecture into the codebase merely because it appears here. First compare it with existing decisions and obtain approval for changes.

## 6. Protocol and cryptographic design principles

Any proposed protocol should be reviewed for at least the following:

- High-entropy, unpredictable challenges generated by a cryptographically secure random source.
- Challenge expiry, one-time use, server-side binding to the initiating session and intended operation, and atomic consumption to prevent replay/races.
- Explicit relying-party/origin binding and domain separation.
- Canonical, unambiguous serialization of the signed message; versioned fields and strict parsing.
- Binding to credential ID, account/subject, operation, protocol version, relying-party identity, challenge, and relevant session context.
- Signature verification using the registered public key and the correct ML-DSA parameter set.
- No private-key transmission to the backend, browser extension, or other host component.
- Safe handling of errors, retries, rate limits, and credential revocation.
- Key lifecycle: generation, enrollment, storage, backup/recovery policy, rotation, revocation, and destruction.
- Clear separation of authentication, authorization, user presence, and user verification.

Do not invent cryptographic constructions. Prefer standards and vetted libraries. Any custom signed-message encoding, KDF, AEAD selection, key derivation, or protocol state machine needs explicit specification and cryptographic review. Security-sensitive randomness must come from an appropriate cryptographic RNG. Avoid hand-rolled primitives.

## 7. Software vault principles

A software vault is not equivalent to a hardware security boundary. If the host is compromised while a private key is unlocked, malware may be able to extract the key from process memory or misuse the signing interface.

A vault specification should define:

- Threat assumptions and what the vault does not protect against.
- Password/passphrase handling and a suitable password KDF with parameters selected from current guidance and measured on target devices.
- Authenticated encryption (AEAD), nonce handling, associated data, versioning, and metadata integrity.
- Per-vault or per-credential key hierarchy and separation of encryption keys from authentication/signing keys.
- Unlock, lock, timeout, failed-attempt handling, backup, restore, migration, revocation, and secure deletion limitations.
- Database schema and migration/version compatibility.

Do not store private signing keys in plaintext or log them. Do not claim encrypted-at-rest storage prevents extraction from a compromised unlocked process.

## 8. Hardware direction — research plan, not implementation claim

### 8.1 Functional concept

A physical token should hold the private credential and perform ML-DSA signing internally. The host sends a structured request/message; the token returns a signature and public metadata as needed. The private key should not leave the token.

A software authenticator typically performs signing on the host CPU. Encrypting a private key in a local database protects it at rest but does not prevent a compromised host from accessing it after unlock or abusing the signing process.

### 8.2 MCU prototype

An MCU token may include:

- USB-capable MCU running firmware and a strict request parser.
- Flash/nonvolatile storage for firmware and credential material.
- USB HID or CDC transport, selected after protocol and platform analysis.
- Physical button and LED for user-presence/approval and status.
- Optional secure element only if its exact supported algorithms, key import/generation behavior, interfaces, and certification are verified.

A development board such as RP2040/Pico or an STM32 board can be useful for prototyping, but a general-purpose MCU board is not automatically a secure element. RP2040-class boards have constrained SRAM and typically external flash; check exact board specifications and memory headroom before selecting one. Do not claim tamper-resistant key isolation without evidence.

### 8.3 Host-to-token security

A button press may establish user presence, but it does not necessarily prove which website or transaction the host is displaying. A malicious host could potentially request signatures for attacker-chosen messages. The protocol should bind the signature to the relying party and operation, and the token's authorization policy must be analyzed. A trusted display or independent confirmation channel may be needed for meaningful transaction confirmation.

### 8.4 FPGA option

An FPGA is optional research, not a prerequisite. It may accelerate selected ML-DSA arithmetic (for example NTT, modular arithmetic, or polynomial multiplication), while a processor/MCU handles protocol, USB, and policy. FPGA implementation is not inherently secure. Measure end-to-end latency, data-transfer overhead, memory, resource utilization, power, and security implications; do not report only the arithmetic-core speedup.

### 8.5 Hardware milestones

1. Software baseline and protocol specification.
2. MCU functional prototype: key generation, signing, public-key export, USB transport, request validation, user-presence signal, and measurements.
3. Hardened design: secure boot/update, key protection, anti-replay, authorization policy, side-channel/fault analysis, recovery, and physical attack considerations.
4. Optional FPGA accelerator study with a measured software baseline.

Prefer generating a fresh credential inside the hardware token, registering and verifying it, and only then revoking the software credential after recovery safeguards. Do not assume exporting an existing software private key into hardware is the right migration path.

## 9. Research novelty and prior-art discipline

Potential research directions are hypotheses, not established novelty claims:

- Policy-enforced authorization for host-to-token ML-DSA signing requests.
- Secure migration from software-held credentials to hardware-backed credentials without exporting private keys.
- Memory-aware ML-DSA execution on constrained authenticators.
- Side-channel- and fault-aware ML-DSA authentication hardware.

Before claiming novelty:

1. Search current academic literature, standards, patents, and deployed products.
2. Verify each paper's title, authors, venue, year, DOI/arXiv/ePrint identifier, and actual claims from the primary source.
3. Compare the proposed contribution with the closest prior art, not just broad PQC surveys.
4. State the exact gap, threat model, baseline, contribution, and measurable evaluation.
5. Distinguish a new engineering integration from a novel cryptographic primitive or protocol.

Do not reuse unverified citations from earlier brainstorming as authoritative references.

## 10. Phase 1 documentation tracker — historical baseline

Phase 1 was previously defined as **specification and research only; no application code**. The exit gate was:

> “The team can explain exactly what QuantumKey claims to protect, what it does not protect, how registration and login should behave, and which assumptions still require experimental proof.”

The eight planned documents are:

1. `docs/TERMINOLOGY_AND_BOUNDARIES.md`
2. `docs/REQUIREMENTS.md`
3. `docs/API_CONTRACTS.md`
4. `docs/CRYPTO_FEASIBILITY.md`
5. `docs/VAULT_SPECIFICATION.md`
6. `docs/THREAT_MODEL.md`
7. `docs/EXPERIMENT_PLAN.md`
8. `docs/MILESTONE_ACCEPTANCE.md`

All eight documents now exist and were reconciled with the prototype on 2026-11-06. Their status is tracked in `docs/MILESTONE_ACCEPTANCE.md`, which replaced the earlier `PHASE1_STATUS.md`. Keep them in step with the code when either changes.

## 11. Change and commit workflow (only after approval)

For each approved task:

1. Restate the approved scope and files.
2. Inspect relevant source/docs and current Git status.
3. Make the smallest coherent change.
4. Review the complete diff for correctness, scope, secrets, and accidental changes.
5. Run the test suite (and the PostgreSQL server tests if server or database code changed); fix or report any failure before going on.
6. Stage only the intended files.
7. Create one focused local micro-commit when committing is within the approved scope.
8. Use a neutral project-focused commit message. Never mention Claude, AI, agent, or tool attribution.
9. Report changed files, commit hash if created, test results (and anything not tested), and remaining risks.
10. Stop. Never push.

If the user asks only for a draft or audit, do not commit.

## 12. Required agent handoff sequence

When beginning work in the actual repository:

1. Read this entire `skill.md`.
2. Perform the read-only repository and directory audit in Section 3.
3. Compare the actual docs against the eight Phase 1 drafts and current tracker.
4. Report the evidence-based current state and prioritized remaining work.
5. Wait for explicit user approval before editing, coding, committing, spawning subagents, or changing project scope. Running the tests needs no approval (rule 2).

**Do not start implementation or edit project files until the audit findings have been reported and the user approves the next scope.**
