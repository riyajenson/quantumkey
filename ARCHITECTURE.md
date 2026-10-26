# QuantumKey Architecture

## Architectural goal

QuantumKey must support a software authenticator first while allowing the cryptographic signing operation to move onto physical hardware later. The authentication server should not require a new login protocol when that migration happens.

## System overview

```text
Browser or Demo Client
          |
          | HTTPS / WebAuthn-inspired flow
          v
FastAPI Authentication Server
          |
          | Registration and login challenges
          v
QuantumKey Desktop Authenticator
          |
          | SigningBackend interface
          +-------------------------+
          |                         |
          v                         v
Software ML-DSA Backend       Future USB Backend
liboqs / liboqs-python        USB Serial or HID
                                    |
                                    v
                           FPGA / Pico / MCU
                           Hardware ML-DSA signing
```

## Components

### 1. Browser or demo client

The client represents a website or application requesting registration or login. During early development it may be a simple demonstration interface rather than a browser-integrated WebAuthn client.

Responsibilities:

- start registration or login;
- display the result;
- communicate with the FastAPI server over HTTPS;
- avoid handling authenticator private keys.

### 2. FastAPI authentication server

The server is the relying service. It trusts a credential only after verifying a valid signature for a fresh challenge.

Responsibilities:

- manage users and registered credentials;
- store credential IDs, public keys, algorithm identifiers, service information, and device identifiers;
- generate cryptographically random registration and authentication challenges;
- enforce short challenge expiration;
- enforce single-use challenge consumption;
- bind challenges to the intended user and operation;
- verify ML-DSA signatures;
- return explicit success or failure results;
- record safe operational metrics without logging secrets.

The server must never receive or store an authenticator private key or plaintext PIN.

### 3. QuantumKey desktop authenticator

The authenticator is the security boundary that owns credentials and authorizes signatures.

Responsibilities:

- create credentials for users and services;
- manage multiple stored credentials;
- maintain a persistent device identity;
- unlock the local vault after PIN verification;
- obtain challenges from the server;
- ask for local user approval where appropriate;
- request signing through the configured backend;
- return public keys during registration and signatures during authentication;
- expose timing measurements without exposing private material.

The first interface will be a CLI. A PySide6 GUI will use the same application services later rather than reimplementing cryptography or vault logic.

### 4. Encrypted local vault

The authenticator vault stores local credential records in SQLite.

Example logical record:

```text
credential_id
service_name
public_key
encrypted_private_key or opaque_hardware_key_handle
algorithm
device_id
created_at
```

The vault must:

- derive an encryption key from the PIN using a memory-hard password KDF;
- use authenticated encryption for private-key material;
- store a unique random salt and necessary encryption metadata;
- detect an incorrect PIN or modified ciphertext;
- never store the PIN or plaintext private key;
- support credential creation, lookup, listing, and deletion;
- support future schema migration.

### 5. Signing backend

The signing backend is the main hardware-migration boundary. Higher-level registration and authentication logic should not depend directly on `liboqs`.

Its logical capabilities should include:

- enumerate supported algorithms and device capabilities;
- generate a keypair;
- return the public key and an opaque key reference;
- sign a canonical message using that key reference;
- verify signatures where appropriate;
- delete or retire a key;
- report device presence, timeout, cancellation, and safe error information;
- report operation timings and output sizes.

An opaque key reference is preferable to passing private-key bytes through the application. A software backend can resolve it to encrypted vault material, while a hardware backend can interpret it as a slot or key handle.

### 6. Software ML-DSA backend

The initial backend uses Open Quantum Safe:

```text
Authenticator service
        |
        v
SigningBackend
        |
        v
liboqs-python
        |
        v
liboqs ML-DSA implementation
```

QuantumKey will initially evaluate ML-DSA-44, ML-DSA-65, and ML-DSA-87. The default variant will be selected after Phase 1 validation and measurements.

### 7. Future USB hardware backend

The future backend sends a signing request to an attached device. Ideally, the private key is generated and retained on that device.

```text
Host: canonical message + opaque key handle
                    |
                    v
             USB Serial or HID
                    |
                    v
Hardware: authorize and sign without exporting the private key
                    |
                    v
Host: signature + safe status information
```

Hardware support must consider transport framing, device discovery, timeouts, secure randomness, protected key storage, firmware authenticity, PIN retry enforcement, side-channel resistance, and fault handling.

## Registration flow

```text
1. Client asks the server to begin registration.
2. Server creates a short-lived registration challenge.
3. Authenticator generates a new ML-DSA credential.
4. Authenticator stores the private key locally in encrypted form.
5. Authenticator proves possession by signing the registration data/challenge.
6. Authenticator sends the public key, credential metadata, and proof.
7. Server verifies the proof and stores the public credential.
8. Server marks the registration challenge as used.
```

If registration fails, the design must define whether the new local credential is rolled back, marked pending, or safely retried.

## Login flow

```text
1. Client asks the server to begin login for a user/service.
2. Server selects an allowed credential and creates a fresh challenge.
3. Authenticator finds the corresponding local credential.
4. User unlocks/authorizes the authenticator.
5. Signing backend signs the canonical authentication message.
6. Authenticator returns the credential ID and signature.
7. Server verifies the signature with the registered public key.
8. Server consumes the challenge and returns success or failure.
```

## Canonical signed message

Signing only raw random challenge bytes is too weak for the eventual protocol. The signed message should be deterministic and bind at least:

- protocol name and version;
- operation type, such as registration or authentication;
- server/relying-service identity;
- challenge identifier and challenge bytes;
- credential identifier when already known;
- user/account binding where appropriate;
- algorithm identifier;
- expiry or issued-at information if required by the final protocol.

The exact encoding will be decided and tested before the authentication API is considered stable.

## Server data model

Initial concepts:

### User

```text
id
username
created_at
```

### Credential

```text
id
user_id
credential_id
service_name
public_key
algorithm
device_id
created_at
status
```

### Challenge

```text
id
user_id
purpose
challenge
expires_at
used_at
created_at
```

The server schema contains no private-key field.

## Trust boundaries

```text
Untrusted network
    |
    +-- client/server HTTPS boundary
    |
Authenticator process boundary
    |
    +-- encrypted vault boundary
    |
    +-- optional host/USB device boundary
    |
Hardware physical boundary
```

Each boundary requires explicit validation, safe error handling, replay resistance, size limits, and secret-safe logging.

## Measurement points

Instrumentation should make the following measurable without changing cryptographic behavior:

- key-generation latency;
- signing latency;
- verification latency;
- private/public key and signature sizes;
- request and response sizes;
- vault and server database growth;
- authentication throughput and latency percentiles;
- software-versus-hardware performance.

## Non-goals for the first version

- full W3C WebAuthn or CTAP compliance;
- browser or operating-system passkey integration;
- certified hardware security;
- production deployment;
- multi-device authorization;
- adaptive classical/post-quantum hybrid authentication;
- custom implementation of cryptographic primitives.

These may be explored only after the core software authentication flow is stable.
