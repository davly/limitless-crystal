# limitless-crystal

Cohort-canonical Crystal 1.0+ SDK for the Limitless ecosystem.

## What it ships

- **`Limitless::MirrorMark`** — L43 Mirror-Mark v1 sign/verify with KAT-1 anchor.
- **`Limitless::Honest`** — R143 LOUD-ONCE-WARNING-FLAG primitive + Severity vocab.
- **`Limitless::Legal`** — R166 LIABILITY-FOOTER-CONST + UK GDPR statutory refs.
- **`Limitless::KAT`** — KAT-1 parity assertion re-export.

## R151 KAT-1 cross-substrate firewall

```
239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca
```

Reproducible offline (no Crystal toolchain involved):

```sh
printf '\x01' > /tmp/kat1.bin
printf '\x00%.0s' {1..32} >> /tmp/kat1.bin
openssl dgst -sha256 -mac hmac -macopt key: /tmp/kat1.bin
# → HMAC-SHA256(stdin) = 239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca
```

## Install

In your `shard.yml`:

```yaml
dependencies:
  limitless-crystal:
    github: davly/limitless-crystal
```

Then:

```sh
shards install
```

## Use

```crystal
require "limitless-crystal"

# Mirror-Mark
corpus  = Bytes.new(32) { |i| i.to_u8 }  # your lore-corpus SHA-256
payload = "your payload".to_slice
key     = "your hmac key".to_slice
mark    = Limitless::MirrorMark.sign(corpus, payload, key)
Limitless::MirrorMark.verify(mark, corpus, payload, key)  # raises on tamper

# Boot-time KAT-1 self-test
Limitless::MirrorMark.assert_kat1_parity

# LoudOnce host-responsibility advisory
adv = Limitless::Honest::Advisory.new(
  code: "MY_HOST_NO_DSAR",
  severity: Limitless::Honest::Severity::WARN,
  message: "DSAR endpoint not wired",
  doc_link: "docs/dsar.md"
)
Limitless::Honest.loud_once(adv)
```

## Test

```sh
crystal spec
```

## License

Apache-2.0. Cohort-canonical literals (KAT-1 hex, `[LOUD-ONCE-WARNING]`,
`IMPORTANT:` alert prefix, `lore@v1:` mark prefix) are byte-aligned with
the Go canonical foundation. Drift = parity fail.
