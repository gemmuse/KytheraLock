# KytheraLock design document

**Status:** DRAFT. Decisions are recorded in section 6. Items still marked
**TO BE DECIDED** need an answer before the code that depends on them.

This document explains *why* KytheraLock is built the way it is. Comments in
the source explain individual pieces; this is the overview.

---

## 1. Goal and scope

KytheraLock is an open-source, **self-hosted** password manager written in
C++, using [libsodium](https://doc.libsodium.org/) for all cryptography and
SQLite for storage.

The idea: individuals and organisations can run a password manager on a
server **they own** (a home machine or a corporate server), and be confident
that even if that server is fully compromised, the stored secrets remain
protected.

### Version 1 includes
- One vault, protected by one master password.
- Storing, listing and retrieving named secrets.
- Locking and unlocking the vault.
- A command-line client.

### Version 1 deliberately does NOT include
- Multiple users or sharing (the design must not prevent it, see section 6).
- A graphical or browser client (planned later).
- Syncing between devices.

### Guiding rules
- **Never invent our own cryptography.** We only combine well-known libsodium
  functions. If something is not provided by libsodium, we stop and think.
- **The server is not trusted with secrets.** See section 5.

---

## 2. Threat model

A threat model says who we are defending against, so we know what "secure"
means for this project.

### What we defend against
- **Someone steals the vault data (the database file).** They can read all of
  it and try unlimited password guesses offline on powerful computers.
  Defences:
  - Secrets are encrypted (once the real encryption is written).
  - The password is turned into a key by a deliberately slow, memory-hungry
    function (Argon2id), so each guess is expensive.
  - A random salt per vault means guesses cannot be shared between vaults.
  - A **Secret Key** (D11), random and never stored on the server, is mixed
    into the key. Even a weak password cannot be guessed from stolen server
    data alone, because the attacker would also need the Secret Key.
- **A fully compromised server.** Because encryption happens on the client
  (section 5), the server only ever holds encrypted data and never sees the
  password or any key.
- **Timing attacks on the password check.** The verifier is compared in
  constant time.

### What we do NOT defend against (yet)
- **Malware on the user's own machine** while the vault is unlocked. It could
  read the key from memory or watch typed input.
- **A malicious client.** Zero-knowledge only holds if the client code is
  honest. If a hostile server could *deliver* the client (e.g. a web page or
  extension update), it could deliver a tampered one. Mitigation to design:
  distribute clients through signed, independently verifiable channels, never
  from the server being protected.
- **Metadata.** A server operator can still see who connects, when, how often
  and roughly how much data is stored, even if contents are encrypted.
- **A weak master password combined with a stolen Secret Key.** Slow hashing
  helps, but "Password1" is still guessable by someone who has the user's
  device or Emergency Kit. The Secret Key protects against server-side theft
  only.
- **Memory being written to disk** (swap file, crash dumps). See D5.
- **Tampering with stored data.** Authenticated encryption (section 6, D2)
  will detect modified ciphertext, but whole-record deletion or rollback is
  not designed for yet.

---

## 3. Key concepts in plain language

| Term | Meaning |
|------|---------|
| **Salt** | Random bytes mixed into the password before scrambling. Not secret. Makes every vault's key unique and defeats pre-computed guess tables. |
| **KDF** (key derivation function) | A deliberately slow scramble that turns a weak password into a strong key. We use **Argon2id**. |
| **Master key** | The 32-byte key derived from password + salt. Never stored. Changes when the password changes. |
| **Vault key** | A random key that actually encrypts the vault's contents. Stored only in *wrapped* (encrypted) form. |
| **Wrapping** | Encrypting one key with another key. |
| **Recovery key** | A random key shown once at creation, able to unwrap the vault key if the password is forgotten. |
| **Secret Key** | A long random value generated on the user's device at account creation and mixed into key derivation (D11). Never sent to the server. A stolen database cannot be password-guessed without it. |
| **Verifier** | A one-way fingerprint of the master key, stored so we can check a typed password without storing the key. |
| **Nonce** | A "number used once": a unique value required by each encryption. Reusing one with the same key can break the encryption. |
| **Constant-time compare** | Comparing secrets in a way whose duration does not depend on how many bytes match. |

---

## 4. How unlocking works (implemented today)

### Creating a vault (`Vault::InitialiseNewVault`)
1. Generate a random 16-byte **salt**.
2. Derive the **master key** from password + salt using Argon2id.
3. Compute the **verifier** = keyed BLAKE2b hash of a fixed string, keyed with
   the master key.
4. Store the salt and verifier (base64 text) in the `meta` table.
5. The master key is **not stored**.

### Unlocking (`Vault::Unlock`)
1. Read the salt and verifier from `meta`.
2. Derive a key from the typed password + stored salt.
3. Compute its verifier and compare with the stored one in constant time.
4. Match: keep the key in memory and mark the vault unlocked.
   No match: throw "Wrong password".

### Locking (`Vault::Lock`)
Overwrite the key in memory with zeros (`sodium_memzero`) and mark the vault
locked.

### Parameters (currently hard-coded)
| Setting | Value |
|---------|-------|
| Algorithm | Argon2id (`crypto_pwhash_ALG_ARGON2ID13`) |
| Passes (`opslimit`) | 3 |
| Memory (`memlimit`) | 64 MB |
| Salt size | 16 bytes |
| Master key size | 32 bytes |
| Verifier size | 32 bytes |

> Changing these today would make existing vaults unopenable. Decision D3
> fixes this by storing the parameters inside each vault.
>
> Note: today's code derives the master key from the password and salt only.
> Decision D11 adds a Secret Key to this derivation, which will change it.

---

## 5. Architecture: client-side cryptography (decided)

**All encryption, decryption and key handling happens in the client. The
server stores encrypted data only.**

```
Client (CLI now; UI / browser extension later)
   - asks for the password
   - derives keys, encrypts, decrypts, searches
   - never sends the password or any key to the server
        |
        |  encrypted data over TLS
        v
Server (on a home or corporate machine)
   - stores encrypted blobs (SQLite)
   - authenticates clients and enforces rate limits
   - cannot read any secret
```

Why: if the server is fully compromised, an attacker gets only ciphertext they
cannot open without each user's password. This is the same principle used by
end-to-end encrypted services such as Proton.

### Consequences for the code
- The crypto and vault logic (`CryptoEngine`, `Vault`, key handling) must live
  in a **shared core library** used by every client, not inside the server
  project. This split is done: `KytheraLock.Core` holds `CryptoEngine`,
  `Vault` and the `IVaultStorage` interface, and depends only on libsodium.
  Core never includes SQLite or server code; storage is reached only through
  `IVaultStorage`, which the SQLite `VaultStorageLayer` implements.
- The server project shrinks to storage, authentication and (later) sync.
- The browser extension will need libsodium compiled to WebAssembly (libsodium
  provides this) so the same primitives run in the browser.

### Why `IVaultStorage` lives in Core but `VaultStorageLayer` does not
The rule is about which code depends on which. `IVaultStorage` says *what Core
needs* ("somewhere to keep encrypted data"), so it lives in Core.
`VaultStorageLayer` is *how* that is done with SQLite, so it lives outside Core.

```
Server (SQLite code) ---implements---> IVaultStorage <---used by--- Vault
                                          (both inside Core)
```

- The interface cannot live in Server: `Vault` (in Core) must know its shape,
  so Core would have to include a Server header while Server already uses
  Core. That circular dependency would undo the split.
- `VaultStorageLayer` cannot live in Core: it needs SQLite and SQL, and then
  every client built on Core (command line, browser extension) would need
  SQLite too. Core must need only libsodium.
- Benefits: a client can supply a different implementation that talks to the
  server over the network, and tests can use a simple in-memory fake instead of
  a real database.
- This is the first version of that seam. When the real server is built (its
  job is storing encrypted blobs), the interface may need to change.

### Still to be decided
- **How the client proves who it is to the server without revealing the
  password.** Direction chosen in D11: derive a *separate* login secret
  (never the encryption key) and keep the interface swappable so a
  password-authenticated protocol (SRP or OPAQUE) can replace it later. The
  exact login exchange still needs designing.
- Transport security (TLS configuration, certificates for home servers).
- How multiple devices obtain the same encrypted vault safely.

---

## 6. Decisions

Each decision records what we chose and why.

### D1. Key hierarchy and password changes
Use **envelope encryption** with a separate vault key:

```
password + Secret Key (D11)
   | (Argon2id + salt, then mixed with the Secret Key)
   v
master key ---- wraps ----> vault key ---- wraps ----> secret key (one per secret)
                                                            | encrypts
                                                            v
                                                       the secret's contents
```

- The master password is changeable and changing it should be easy, but never
  forced (forced rotation tends to produce weaker passwords).
- Changing the password creates a new master key and **re-wraps only the vault
  key**. No secret is re-encrypted.
- Rotating the *vault key itself* is a separate, heavier operation (it
  re-encrypts everything). It is needed when trust changes, e.g. someone with
  access leaves an organisation.

### D2. Cipher (decided)
Use an authenticated cipher from libsodium, preferably **XChaCha20-Poly1305**
(`crypto_aead_xchacha20poly1305_ietf_*`). Authentication means any change to
stored ciphertext is detected. Its large nonce makes randomly generated nonces
safe. Bind each ciphertext to its record (e.g. as "additional data") so rows
cannot be silently swapped.

### D3. Store the key-derivation settings in the vault
Store the Argon2id settings and a **format version** next to the salt in
`meta`, so each vault records how it was made. This lets us raise the cost
over time as computers get faster. On a successful unlock of an out-of-date
vault we can re-derive with stronger settings and re-wrap the vault key.

### D4. Recovery
- **Personal vaults:** at creation, generate a random **recovery key**, show
  it once, and store a second wrapped copy of the vault key under it. It is
  optional but strongly prompted. Because it is random and strong it does not
  need the slow KDF. If the user loses *both* password and recovery key, the
  data is unrecoverable by design.
- **Organisations (later):** **admin recovery** by also wrapping the vault key
  for an administrator's public key.
- Both are the same mechanism: the vault key can be wrapped several times, one
  per way of opening the vault. This is the purpose of the `vault_keys` table.

### D5. Protect keys in memory
Keep keys in a small RAII wrapper (`SecureBuffer`) using `sodium_malloc` /
`sodium_mlock` so they are locked out of swap and wiped on destruction.
Implement alongside the real encryption, since key types change then anyway.

### D6. Secret names are encrypted
Names are encrypted like other contents.
- **Partial search** (e.g. `@google.com`): the client decrypts the names after
  unlock and searches them in memory. At personal or small-team scale this
  takes milliseconds.
- **Exact lookup and the uniqueness rule:** use a keyed hash of the name (a
  "blind index") derived from a key the server does not have, so equal names
  can be matched without revealing them.
- This changes the stored format, so it should be done before real vaults
  exist.

### D7. Sharing
Deferred, not forgotten. Wrapping keys per user (D1, D4) keeps the door open.
Organisational use will make this more important than "eventually", so no
design choice should rule it out.

### D8. Clients
Command-line client first. A UI and browser extension later. The server is a
real network service intended to run on a home or corporate machine.

### D9. Brute-force protection
The server can slow down *online* guessing. Make it configurable, using
increasing delays rather than hard lockouts (a hard lockout lets an attacker
block the real user). Note: nothing can limit *offline* guessing of a stolen
database; Argon2id is the defence there.

---

### D10. The client is never delivered by the server
**Rule (proposed as accepted):** the vault server never delivers the client.
Without this, client-side encryption (section 5) is only as safe as the
server, because a compromised server could hand out a tampered client. A
server-hosted web vault is therefore ruled out; if one is ever added it must be
described as a weaker mode.

**Release checklist (required before any public release, not before
development):**
- Releases are signed with a key that is never on the server; updaters verify
  the signature against a public key built into the client.
- Builds are reproducible, and release hashes are published independently.
- The browser extension bundles all its code and loads nothing remote, and its
  store publishing account is strongly protected.
- Organisations can build from source or deploy clients from their own
  pipeline. Good build instructions are part of the security story.
- **Dependencies are pinned** to exact versions, with hashes checked when they
  are downloaded. Where practical they are vendored in the repository (SQLite
  already is).

### D11. Secret Key and login (modelled on 1Password's two-secret design)
- At account creation the client generates a **Secret Key**: 128 or more bits
  of random data, shown once and printed as an "Emergency Kit". It is stored
  on the user's devices (protected by the operating system's key store where
  possible) and **never sent to the server**. A new device asks for it once.
- The master key is derived from the **password and the Secret Key** together
  (Argon2id on the password, then mixed with the Secret Key using a keyed
  hash). The exact construction needs review before it is built.
- From the master key we derive **two unrelated subkeys** with different
  contexts (`crypto_kdf_derive_from_key`): one for **encryption**, which never
  leaves the device, and one for **login**.
- The client proves its identity to the server using the login subkey. The
  server stores only a hash of it (not the key itself), and never receives
  anything that can decrypt data.
- The login step sits behind a clean interface, so a password-authenticated
  protocol (SRP or OPAQUE) can replace it later without touching the
  encryption.
- **OPAQUE is deferred, not rejected.** Most of its benefit (the server learns
  nothing it can use to guess passwords offline) is already provided by the
  Secret Key, because the login subkey depends on it. libsodium has no OPAQUE,
  so adopting it means depending on a third-party library for the most
  sensitive step. Moving later is cheap: the client holds the password at each
  login and can enrol the new record then. Revisit once the available C/C++
  libraries and their audit status have been researched.
- Why: with a Secret Key, someone who steals the whole server database cannot
  brute-force it by guessing passwords, however weak the password is.
- Cost: users must keep the Secret Key safe. Losing it is as serious as losing
  the password (see open question 4).

### D12. Emergency Kit
- The kit is a **printable sheet** to keep somewhere physically safe. It holds
  the Secret Key, the recovery key (D4), the server address and the account
  name. It never contains the master password (a blank line may be left for
  the user to write it).
- An optional **digital export** is allowed, encrypted with libsodium under a
  passphrase the user chooses, with a clear warning. A passworded ZIP is
  **not** used: the older ZIP encryption is weak, and a kit locked with the
  master password would be useless in exactly the case it exists for (a
  forgotten password).
- **Important difference from 1Password:** there, a stolen kit is not enough
  because the attacker still needs the password. Here, the **recovery key
  unwraps the vault key on its own**, so a kit containing both keys is
  everything an attacker needs. The kit must be treated like a house key.
- **Still to decide:** one kit holding both keys (simple), or the recovery key
  kept apart from the Secret Key. Current leaning: one kit with a detachable
  recovery section, so the user can choose to store it separately.

### D13. Revoking users
- Users can be **disabled** (cannot log in) or **removed**. A revoked user is
  never able to retrieve key material again: the server refuses to serve
  their wrapped keys, and removal deletes them.
- **Cryptographic limit:** a user who once held the vault key can still
  decrypt anything they previously downloaded or can still obtain. Changing a
  password does not help, because under D1 it only re-wraps the *same* vault
  key. Revocation therefore has three tiers:
  1. **Disable** the account.
  2. **Remove** their wrapped key from the server.
  3. **Rotate the vault key** and re-encrypt everything. This is the real fix
     when compromise is suspected.
- The organisation should also change the actual secrets in the vault that the
  user could see.

### D14. Auditing
- Configurable level from **none** through **minimal** and **standard** to
  **full**.
- The log records *events* (logins, failed logins, users added, disabled or
  removed, vault accessed), never *content*.
- **Never logged, at any level:** keys, secret values, passwords, the Secret
  Key, login secrets, session tokens.
- Enforced by design, not discipline: key and secret types (see `SecureBuffer`,
  D5) have no way to be written to a stream or log.
- The audit log is itself metadata, so it needs protecting like other server
  data.
- It is stored as a log, and **how long it is kept is configuration**, set by
  the owner alongside the audit level.

### D15. Backup and restore (future user story)
- Dump the database to a file. Because it holds only ciphertext, a dump is
  far safer than a normal database backup, although it still contains wrapped
  keys and metadata.
- Use SQLite's own backup facility (not a plain file copy while the server is
  running), and test restores.
- A **plaintext export** (e.g. CSV) is a separate, client-side feature with
  explicit warnings. It is not part of the backup.

### D16. The server never trusts the client
The mirror image of D10. D10 means the *client* does not trust the server;
this means the *server* trusts nothing it is sent. Like a game server that
assumes every client may be modified, the server verifies everything itself:
- **Identity:** every request is authenticated. Who the client *claims* to be
  (user id, vault id) is never taken on trust.
- **Permission:** for every action, the server checks that this user may
  access this vault or record. Wrapped keys are served only to the user they
  belong to, and never to disabled or removed users (D13).
- **Structure:** all input is validated: sizes, lengths, format versions,
  field counts, nonce and key lengths. Over-large or malformed requests are
  rejected before they touch storage.
- **Abuse limits:** rate limits (D9) and per-user storage quotas.
- **Consistency:** version numbers on records so a stale or replayed client
  cannot silently overwrite newer data.
- **Failure behaviour:** reject by default, and log the event (never the
  content, D14).

**Limit to be aware of:** the server cannot read encrypted data, so it cannot
check that a ciphertext is genuine. A malicious client can store garbage, but
only in vaults it already has permission to write to, within its quota. The
server's job is therefore to control *who* may do *what* and *how much*, not
to judge the content.

### D17. Shared vaults and user keys
Builds on D1 (vault key), D13 (revocation) and D16 (server permissions).

- **One vault key per vault; one wrapped copy per user.** Each user holds
  their own copy of the vault key, locked so only they can open it. All the
  copies unlock to the same vault key.
- **Each user has their own independent key pair** (the planned `users` table:
  a public key, plus the private key stored encrypted). User keys are *not*
  derived from a shared secret. If they were, whoever held the shared secret
  could compute everyone's keys, and changing it would force every user to
  regenerate.
- **Adding a user:** an administrator's client "seals" the vault key to the new
  user's public key (libsodium `crypto_box_seal`) and uploads the result. No
  password is shared, and the server only ever stores the sealed copy.
- **Removing a user:** follow the tiers in D13. Deleting their wrapped copy
  never affects anyone else's, so nobody else has to do anything. Rotating the
  vault key is only for suspected compromise.
- **The layers are locks opened on the user's device**, never combined by the
  server: master key, then vault key, then each secret's key. The server never
  holds, receives or combines any key, and the client never sends a secret key
  to the server.
- **The server keeps its own membership list** (which users may fetch which
  vault) and checks it on every request (D16). Membership controls who can
  *get* the locked data; the wrapped keys control who can *read* it. Both are
  needed.
- **Considered and rejected:**
  - Sending a client's secret key to the server so it can combine it with the
    vault key. This requires the server to hold keys and reverts to the model
    D10 and section 5 exist to avoid.
  - Deriving all user keys from one shared key (see above).

**Open (item 8 in section 7):** how an administrator knows a public key really
belongs to the intended person.

---

## 7. Open questions: TO BE DECIDED

1. The exact login exchange between client and server (D11). Research
   available OPAQUE libraries and their audit status before deciding whether
   to adopt it.
2. ~~Confirm the cipher~~ Decided: D2.
3. Exact format of the wrapped-key and recovery-key records, including how
   they are versioned. Needs a dedicated discussion. Topics: what each record
   carries (version, algorithm id, KDF settings, nonce, ciphertext) and the
   encoding (binary, base64, or a structured format).
4. The Secret Key (D11) and the recovery key (D4) are separate things: the
   Secret Key is needed to derive the master key, while the recovery key
   reopens the vault if the *password* is forgotten. Do we need both, and
   could one Emergency Kit hold them? How are they presented (grouped
   characters, checksum, version prefix) and how do we encourage safe storage?
   Direction recorded in D12; the one-kit versus separate-recovery-key choice
   is still open.
5. ~~Adding and removing users~~ Decided: D13 (removing) and D17 (adding and
   sharing).
6. ~~Audit logging~~ Decided: D14 (stored as a log; level and retention are
   configurable).
7. ~~Backup and restore~~ Recorded as a future user story: D15.
8. **Trusting a new user's public key (D17).** When an administrator fetches a
   new user's public key from the server, a hostile server could substitute its
   own, and the administrator would then seal the vault key to the attacker.
   Candidate defences: compare a short fingerprint out of band, or have the
   organisation sign its users' keys. Related: the recipient should be able to
   tell the sealed copy came from a genuine administrator (a sealed box alone
   does not prove who sent it), so authenticated or signed key delivery needs
   considering.

---

## 8. Status and roadmap

### Done
- Salt, Argon2id key derivation, verifier, constant-time check.
- Lock / unlock with key wiping.
- SQLite storage layer and schema (tables below).
- Base64 helpers.
- The start-up crash in the test program is fixed (it now checks
  `Vault::IsInitialised()`).

### Storage tables

| Table | Purpose | Status |
|-------|---------|--------|
| `meta` | Key/value settings: `kdf_salt`, `kdf_verifier`. | In use |
| `vaults` | A named collection of secrets. v1 has one row, id 1. | In use |
| `secrets` | One row per item: name, nonce, ciphertext, and its own encrypted key plus nonce. | In use (stored unencrypted for now) |
| `users` | Public key, plus the private key stored encrypted. | Planned, unused |
| `vault_keys` | The vault's key, wrapped separately for each user or recovery method. | Planned, unused |

Binary values are stored as base64 text. Secret names are currently plain
text, which D6 will change.

### Known problems
- `CryptoEngine::Encrypt` / `Decrypt` are stubs: **secrets are stored
  unencrypted**. Do not store real passwords yet.
- The master key is held in a normal `std::vector` (see D5).
- The test program (`Server.cpp`) always re-adds "github", so a second run
  reports a duplicate-name error.
- The test program (`Server.cpp`) still plays both client and server in one
  process, and the Server project is only fully configured for Debug x64
  (Release x64 and Win32 lack the libsodium settings).

### Suggested order of work
1. Confirm D2 and settle the format of the wrapped-key records.
2. ~~Split the project: a core library (crypto + vault) and a server.~~ Done.
3. Implement real `Encrypt` / `Decrypt` with tests using known inputs.
4. Implement the vault key, per-secret keys and key wrapping (D1), plus
   `SecureBuffer` (D5), stored KDF settings (D3), and the Secret Key with
   separate encryption and login subkeys (D11).
5. Password change, then the recovery key (D4).
6. Encrypted names and blind index (D6).
7. Tests: wrong password, tampered data, lock/unlock cycles, password change,
   recovery.
8. Research and decide the authentication protocol, then build the network
   layer and the command-line client.

---

## 9. Building

Requires libsodium. Set these environment variables:
- `KYTHERALOCK_LIBSODIUM_INCS`
- `KYTHERALOCK_LIBSODIUM_LIBS_X64`

Open `src/KytheraLock.sln` in Visual Studio.
