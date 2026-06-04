# Security Policy — limitless-crystal

This document is the threat model for **`limitless-crystal`**, the cohort-canonical
Crystal SDK shipping four primitives:

- `Limitless::MirrorMark` — L43 Mirror-Mark v1 HMAC-SHA256 sign/verify.
- `Limitless::Honest` — R143 LOUD-ONCE-WARNING-FLAG advisory primitive.
- `Limitless::Legal` — R166 liability-footer + UK GDPR statutory reference constants.
- `Limitless::KAT` — KAT-1 cross-substrate parity assertion re-export.

It is written against the on-disk source (`src/*.cr`), not a template. Read it
before trusting a Mirror-Mark produced or verified by this library.

## 1. What this library is — and is not

**It is** a dependency-free (Crystal stdlib only: `openssl/hmac`, `openssl/digest`,
`base64`) set of pure functions and constants. There is **no network I/O, no file
I/O, no environment-variable reads, no process spawning, and no global mutable
state other than the in-process `Limitless::Honest` once-registry**. Calling
`sign`, `verify`, or any `Legal` helper does not phone home, does not open a
socket, and does not read disk.

**It is not** an identity, authorisation, or transport-security layer. A valid
Mirror-Mark proves only that *whoever held the HMAC key* signed *this payload
under this corpus prefix*. It does not prove who that party was, when they signed,
or that they were authorised to. It is a symmetric MAC, **not** a public-key
signature: any party able to verify a mark also holds the key needed to forge one.

## 2. Trust boundaries

| # | Boundary | What crosses it | Who is trusted |
|---|----------|-----------------|----------------|
| B1 | **Caller → `sign` / `verify`** | `corpus_sha` (32 bytes), `payload` bytes, `key` bytes | Caller supplies and protects the key. The library never persists, logs, or transmits it. |
| B2 | **`Marker` construction** | `corpus_sha`, `key`, optional `on_warn` callback | `Marker` refuses an empty key (`EmptyKeyError`) and flags an all-zero corpus or key as a placeholder. The host decides what to do with that warning. |
| B3 | **Untrusted mark string → `verify`** | A `String` of unknown provenance | The library treats the mark body as adversary-controlled: it bounds the version prefix, base64url decode, and body length **before** any constant-time compare. |
| B4 | **`Legal` text → host response** | Statutory constants, `Page` / `Acceptance` records | The host is responsible for replacing `placeholder` config and for surfacing the un-reviewed `DEFAULT_PLACEHOLDER_ALERT` banner. |

Everything inside the process boundary (the caller, the key in memory, the host
that wires advisories to a logger) is trusted. Everything arriving as a mark
string or a payload to verify is **untrusted**.

## 3. Attack surface and the properties relied upon

### 3.1 Mark verification (`MirrorMark.verify` / `verify_bool`)

The dangerous input is the third-party mark string. `verify` defends in this order
(`src/mirrormark.cr`):

1. **Corpus length check** — rejects a `corpus_sha` that is not exactly 32 bytes
   (`InvalidCorpusLengthError`) so a short corpus can never under-cover the HMAC.
2. **Version-prefix check** — requires the literal `lore@v1:` prefix
   (`UnknownMarkVersionError`); a future-version mark is rejected, not
   silently mis-parsed.
3. **Base64url decode** — a malformed body returns `nil` and raises
   `MalformedMarkError` rather than throwing an unhandled exception.
4. **Body length check** — the decoded body must be exactly 40 bytes
   (8-byte corpus prefix + 32-byte HMAC); otherwise `MalformedMarkError`.
5. **Corpus-prefix compare** — `constant_time_equal`, then
6. **HMAC compare** — `constant_time_equal` of the embedded digest against a
   freshly recomputed `HMAC-SHA256(0x01 ‖ corpus_sha ‖ payload, key)`.

`verify` returns `nil` on success and raises a **typed sentinel** on every
failure path; it never returns a partial or "maybe" result. `verify_bool` is a
thin boolean wrapper that catches only `MirrorMark::Error`.

### 3.2 Constant-time comparison — what is and is not protected

- **Secret-dependent comparisons** (the corpus-prefix and HMAC-digest checks in
  step 5–6) use the in-repo `constant_time_equal`, a length-checked
  XOR-accumulate fold. This is the standard mitigation against a timing oracle
  that would otherwise let an attacker recover a valid HMAC byte-by-byte.
- **Non-constant-time steps** (base64url decode, the `lore@v1:` prefix check,
  body-length check) operate only on the **already-public mark string and its
  length** — they reveal nothing about the secret key. This is by design; do not
  "fix" it by making prefix parsing constant-time, and do not assume the decode
  step hides anything.

> Caveat for auditors: `constant_time_equal` is a hand-rolled helper, not a
> vetted platform primitive. Its constant-time property holds for equal-length
> inputs (length is checked first and returns `false` early). If you port or
> refactor it, re-establish that the comparison loop has no data-dependent
> branch or early return.

### 3.3 The HMAC key (highest-value secret)

- The key is a symmetric secret. Its compromise lets an attacker forge **any**
  mark under any corpus/payload. Rotate it the way you would rotate any HMAC
  secret; this library has no key-rotation, key-derivation, or keyring facility —
  that is the host's responsibility.
- The library never writes the key to a log, an error message, or the emitted
  mark. Error strings are static text and never interpolate key or payload bytes.
- `Marker` is fail-closed against accidental key loss: an empty key raises
  `EmptyKeyError` at construction. An **all-zero** key or corpus is *not* rejected
  (KAT-1 vectors legitimately use them) but is flagged via `using_placeholder_key?`
  / `using_placeholder_corpus?` and a one-shot `STDERR` warning, so production
  paths can detect "I am signing with a placeholder and these marks will not pass
  cold-verify."

### 3.4 `Limitless::Honest` once-registry (process state + memory)

- `LoudOnceSingleton` keeps an unbounded in-process `Hash(String, Bool)` of seen
  advisory codes. Advisory **codes** are expected to be a small, static,
  developer-authored set. **Do not key advisories on attacker-controlled or
  high-cardinality strings** (e.g. per-request IDs): that turns the dedupe map
  into an unbounded-growth (memory-exhaustion) vector. Treat the code as a
  compile-time constant.
- `reset` clears the registry and is documented **TEST-ONLY**; calling it in
  production re-arms every "loud-once" advisory and defeats the dedupe contract.
- The singleton is not synchronised. In a multi-fiber host the worst case is a
  duplicate emission of the same advisory under a race — informational, not a
  security failure — but callers needing strict once-semantics across fibers
  should serialise access.

### 3.5 `Limitless::Legal` — data sensitivity, not crypto

- This module ships **legal/statutory text constants and record shapes**, not a
  compliance engine. The `ARTICLE_9_MENTAL_HEALTH_NOTICE` text concerns
  **special-category personal data** under UK GDPR Article 9; the record types
  (`Page`, `Acceptance`) can carry `user_id`, `accepted_from_ip`, and
  `user_agent`. The SDK does not store or transmit these — the host does — so the
  host owns the lawful-basis, retention, and DSAR obligations.
- `DEFAULT_REVIEWED_BY_COUNSEL = false` and the `DEFAULT_PLACEHOLDER_ALERT` banner
  are honest defaults (R166). `body_with_placeholder_alert` prepends the alert to
  any page not explicitly marked counsel-reviewed. **Shipping these constants
  verbatim to end users is a compliance gap, not a code bug** — replace the
  `Legal.placeholder` config and have the text reviewed before relying on it.

## 4. Cryptographic / parity assumptions

- Security rests on **HMAC-SHA256** as provided by Crystal's `OpenSSL::HMAC`. A
  compromise of the underlying OpenSSL build (the only sensitive dependency)
  undermines every guarantee here. Keep the toolchain's OpenSSL patched.
- The **KAT-1 anchor**
  `239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca` is the
  cross-substrate firewall. `assert_kat1_parity` raises on drift. A failing KAT-1
  self-test means this build's HMAC output diverges from the Go canonical
  foundation and from every cohort sibling — **do not trust marks from a build
  that fails KAT-1**, and do not "fix" the test by editing the constant.
- Marks are **not** confidential and **not** replay-protected on their own: a mark
  embeds only an 8-byte corpus prefix plus the HMAC, carries no timestamp or
  nonce, and can be re-presented. If your protocol needs freshness or
  anti-replay, bind a nonce/timestamp into the `payload` you sign.

## 5. Out of scope

- Transport security (TLS), authentication, authorisation, rate-limiting, and
  audit-log durability — all host concerns.
- Key generation, storage, derivation, and rotation — host concerns.
- Asymmetric signatures / non-repudiation — Mirror-Mark is a symmetric MAC by
  design; it cannot prove a signer to a party that does not also hold the key.
- Side channels below the comparison layer (CPU cache, speculative execution,
  power analysis) — not mitigated.

## 6. Reporting a vulnerability

Report suspected vulnerabilities privately. Do **not** open a public issue for a
security report, and do not include live key material or production data in a
report.

- **Contact:** the repository owner via the GitHub repository
  <https://github.com/davly/limitless-crystal> (use a private security advisory
  where available).

Please include: affected version/commit, a minimal reproduction, and the impact
you observed. A KAT-1 parity drift, a verification bypass, a timing-oracle
finding in `constant_time_equal`, or any path that leaks key or payload bytes
into an error/log are treated as high severity.
