# QuantumKey Development Phases

## Working model

Development is divided into reviewable phases. Each phase has a goal, assigned ownership, concrete outputs, and a completion gate. A phase is not complete merely because files or code exist; its evidence, tests, documentation, and review must also be complete.

Branches are organized by phase:

```text
main       Stable, reviewed project baseline
phase-1    Research, requirements, and threat model
phase-2    Architecture validation and technical experiments
...
```

Work should be committed in small, focused commits. Completed phase work should reach `main` through review rather than direct unreviewed development.

## Phase 1: Research, requirements, and threat model

**Goal:** Convert the idea into a precise, testable specification before selecting implementation details.

| Workstream | Assignment |
|---|---|
| Architecture and scope | Define prototype boundaries, system context, terminology, success criteria, and non-goals. |
| Cryptography and hardware | Validate ML-DSA variants, liboqs capabilities, expected key/signature sizes, and hardware constraints. |
| Backend and protocol | Draft registration/login API contracts, challenge lifecycle, error model, and trust boundaries. |
| Authenticator and vault | Define vault, PIN, device identity, credential lifecycle, and user-interaction requirements. |
| Security, QA, and research | Create the threat model, research metrics, test strategy, risk register, and experiment methodology. |

### Outputs

- agreed terminology and system boundaries;
- requirements and non-goals;
- preliminary protocol and API contracts;
- ML-DSA/liboqs feasibility results;
- vault and credential-lifecycle specification;
- threat model and risk register;
- research metrics and experiment plan;
- acceptance criteria for the first functional milestone.

### Completion gate

The team can explain exactly what QuantumKey claims to protect, what it does not protect, how registration and login should behave, and which assumptions still require experimental proof.

## Phase 2: Architecture and technical validation

**Goal:** Validate the highest-risk technical assumptions with isolated experiments before application development.

### Team focus

- **Architecture and scope:** module boundaries, dependency direction, data flows, and architecture decisions.
- **Cryptography and hardware:** reproducible ML-DSA keygen/sign/verify tests and the initial signing-backend contract.
- **Backend and protocol:** FastAPI, SQLAlchemy, PostgreSQL, binary storage, and transaction experiments.
- **Authenticator and vault:** SQLite vault encryption, PIN-derived key, and credential lookup experiments.
- **Security, QA, and research:** validation checklist, cross-platform reproducibility, measurements, and blocker tracking.

### Outputs

- standalone ML-DSA validation results;
- database and API technology validation;
- vault encryption proof of concept;
- draft `SigningBackend` interface;
- architecture decision records;
- development-environment instructions.

### Completion gate

The selected libraries work reproducibly, or all limitations and required alternatives are documented well enough to make a decision.

## Phase 3: Protocol and backend foundation

**Goal:** Establish the server, database schema, challenge lifecycle, and stable message formats.

### Team focus

- **Architecture and scope:** protocol versioning, canonical signed-message format, and integration review.
- **Cryptography and hardware:** algorithm identifiers, public-key validation, and cryptographic error behavior.
- **Backend and protocol:** FastAPI structure, migrations, models, and registration/login endpoints.
- **Authenticator and vault:** minimal authenticator-side API client.
- **Security, QA, and research:** backend tests, test database, fixtures, and continuous-integration plan.

### Outputs

- User, Credential, and Challenge models;
- registration-start and registration-complete APIs;
- login-start and login-complete APIs;
- expiring, single-use challenge handling;
- versioned canonical message specification;
- migration and test infrastructure.

### Completion gate

Challenge generation and consumption pass expiration, replay, mismatch, and concurrency tests.

## Phase 4: End-to-end authentication milestone

**Goal:** Complete the first functional QuantumKey flow.

```text
ML-DSA key generation
        +
server challenge
        +
authenticator signing
        +
server verification
        =
successful authentication
```

### Team focus

- **Architecture and scope:** integration ownership and protocol consistency.
- **Cryptography and hardware:** software ML-DSA backend and crypto instrumentation.
- **Backend and protocol:** server registration/login verification and binding checks.
- **Authenticator and vault:** minimal registration/login CLI.
- **Security, QA, and research:** end-to-end, tampering, replay, negative, and baseline performance tests.

### Completion gate

Valid registration and login succeed repeatedly. Altered signatures, altered messages, expired challenges, reused challenges, and mismatched credentials consistently fail.

## Phase 5: Secure authenticator vault

**Goal:** Turn the demonstration client into a locally protected authenticator.

### Team focus

- **Architecture and scope:** credential lifecycle, recovery, deletion, and security review.
- **Cryptography and hardware:** key serialization, memory exposure, and crypto-storage review.
- **Backend and protocol:** server-side credential/device management and revocation support.
- **Authenticator and vault:** encrypted SQLite vault, PIN unlock, device identity, and multiple credentials.
- **Security, QA, and research:** wrong-PIN, corruption, migration, concurrency, and secret-logging tests.

### Outputs

- PIN-protected encrypted vault;
- multiple credential support;
- device identity;
- credential listing and deletion;
- controlled unlocked sessions;
- vault migration strategy.

### Completion gate

Disk inspection reveals no plaintext PIN or private key, wrong PINs fail safely, and modified vault ciphertext is detected.

## Phase 6: Hardening, observability, and reproducibility

**Goal:** Make the system reliable and measurable enough for research evaluation.

### Team focus

- **Architecture and scope:** architecture/security review and risk prioritization.
- **Cryptography and hardware:** ML-DSA-44/65/87 measurements and classical comparison adapters.
- **Backend and protocol:** audit events, rate limiting, request limits, and PostgreSQL hardening.
- **Authenticator and vault:** PIN sessions, credential selection, and safe local configuration.
- **Security, QA, and research:** Docker, CI, load testing, database-growth tests, and reproducible reports.

### Measurements

- key-generation, signing, and verification latency;
- signature and key sizes;
- request and response sizes;
- database growth;
- authentication throughput;
- error rate and latency percentiles.

### Completion gate

A clean supported machine can reproduce the system and its benchmark results by following the project documentation.

## Phase 7: Desktop GUI

**Goal:** Add a usable desktop interface after the protocol, crypto, and vault layers are stable.

### Team focus

- **Architecture and scope:** ensure GUI boundaries preserve the service architecture.
- **Cryptography and hardware:** review signing approvals and prevent silent authorization.
- **Backend and protocol:** supply only the server APIs genuinely required by the interface.
- **Authenticator and vault:** implement the PySide6 unlock, approval, registration, and credential-management UI.
- **Security, QA, and research:** usability, accessibility, packaging, and regression testing.

### Completion gate

The GUI uses the same tested application services as the CLI and contains no duplicate vault or cryptographic implementation.

## Phase 8: Hardware migration and research extensions

**Goal:** Demonstrate that signing can move outside the desktop application without redesigning server authentication.

### Team focus

- **Architecture and scope:** host-token protocol, capability negotiation, and versioning.
- **Cryptography and hardware:** USB hardware backend, key handles, ML-DSA hardware integration, and hardware benchmarks.
- **Backend and protocol:** verify that the existing server protocol remains compatible.
- **Authenticator and vault:** device discovery, selection, status, timeout, and fallback behavior.
- **Security, QA, and research:** hardware/software comparisons, transport tests, fault tests, and research reporting.

### Possible later extensions

- classical/post-quantum hybrid authentication;
- risk-based algorithm selection;
- multiple-device authorization;
- CPU-versus-FPGA signing decisions;
- hardware-backed PIN retry enforcement.

### Completion gate

Software and hardware backends pass the same signing contract tests, and the server completes authentication without knowing which backend produced the signature.

## Phase review checklist

Before merging a phase into `main`, confirm:

- [ ] requirements and assumptions are current;
- [ ] assigned deliverables are present;
- [ ] security-sensitive behavior has been reviewed;
- [ ] relevant tests or research evidence pass;
- [ ] failures and limitations are documented;
- [ ] no private keys, PINs, tokens, or generated secrets are committed;
- [ ] documentation matches the implementation or experiment;
- [ ] commits are small and reviewable;
- [ ] the working tree is clean;
- [ ] the team approves the phase completion gate.
