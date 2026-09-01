# One version number, several different things — the published landscape, measured

1 September 2026. Jasper, on finding the installed CLI was from May: *"zo oud, zoek dan even of er
nieuwere voorbeelden draaien ofzo?"* — then: *"crates heeft van ons 30+ packages."* Swept. The
answer is not "old". It is that **a version number does not identify contents, and a crate name does
not identify a thing.**

## The whole published footprint: 31 crates

Found by querying crates.io and keeping only crates whose `repository` points at `jaspertvdm` or
`Humotica`. Sorted by downloads.

| crate | version | updated | dl | repo |
|---|---|---|---|---|
| `tibet-zip-core` | 2.3.0 | 6 Aug | 930 | tbz |
| `tibet-zip-mirror` | 2.3.0 | 6 Aug | 482 | tbz |
| `tibet-zip-jis` | 2.3.0 | 6 Aug | 476 | tbz |
| `tibet-zip-airlock` | 2.3.0 | 6 Aug | 469 | tbz |
| `tibet-cortex-core` | 0.3.0 | 16 Mar | 376 | tibet-cortex |
| `tbz-core` | 2.3.0 | 6 Aug | 316 | tbz |
| `tibet-zip-cli` | 2.3.0 | 6 Aug | 291 | tbz |
| `tibet-trust-kernel` | 1.0.0-alpha.5 | 1 Jun | 284 | tibet-trust-kernel |
| `cortex-core` | 0.0.0 | 14 Mar | 260 | tibet-cortex |
| `tbz-mirror` · `tbz-jis` · `tbz-airlock` · `tbz-cli` | 2.3.0 | 6 Aug | 256·251·250·227 | tbz |
| `tibet-cortex-airlock` · `-jis` · `-audit` · `-store` · `-cli` | 0.3.0 | 16 Mar | 246·174·108·104·31 | tibet-cortex |
| `cortex-airlock` · `-jis` · `-audit` · `-store` · `-cli` | 0.0.0 | 14 Mar | 173·130·87·84·36 | tibet-cortex |
| `jis-core` | 0.4.0 | 6 Jun | 120 | jis-core |
| `tibet-core` | 0.1.3 | 31 May | 65 | tibet-core |
| `tibet-dgx` | 0.2.0 | 18 Apr | 55 | tibet-dgx |
| `tibet-iddrop` | 0.3.1 | 3 Jun | 41 | tibet-iddrop |
| `oomllama` | 1.0.0-alpha.2 | 19 Apr | 37 | oomllama |
| `tibet-oomllama` | 0.1.0 | 16 Mar | 32 | oomllama |
| `tibet-airlock` | 0.0.0 | 11 Apr | 28 | tibet-airlock |
| `tibet-airlock-kernel` | 0.2.0 | 29 May | 23 | tibet-airlock-kernel |

Machine-readable: `crates_inventory.json` alongside this file.

### 31 names, roughly 20 things — and the split is deliberate, not a mess

Measured by downloading and unpacking, not by reading names:

    tbz-core 2.3.0        10,975 bytes,  src/ = lib.rs only,  contents: `pub use tibet_zip_core::*;`
                          dependency: tibet-zip-core = "2.3.0"
    tibet-zip-core 2.3.0  27,698 bytes,  src/ = block · envelope · lib · manifest · signature ·
                                                 stream · v2

So the whole `tbz-*` family is a **one-line alias** over `tibet-zip-*`. That is a legitimate
short-name convenience, not accidental duplication, and it should not be described as drift.

    cortex-core 0.0.0     263 bytes  — an empty NAME RESERVATION
    tibet-cortex-core 0.3.0          — the real crate

Also legitimate. So of 31 published crates: ~5 aliases, ~6 reservations, ~20 carrying real content.

**The one that is a genuine split:** `oomllama 1.0.0-alpha.2` (19 Apr) and `tibet-oomllama 0.1.0`
(16 Mar) come from the same repo at different versions on different dates, and `tibet-oomllama` is
82 KB of 14 real source files. Two live names, neither obviously canonical. That one is worth a
decision.

## The finding that costs something: the same number, two contents

`tibet-zip-core` **2.3.0 on crates.io does not contain the producer binding.** This repo's 2.3.0
does. Both call themselves 2.3.0.

    published 2.3.0 (6 Aug)   producer_identity: 0   archive_id: 0
    local 2.3.0 (today)       producer_identity: 6   archive_id: 22

Measured on the unpacked tarball, and the FIRST attempt at measuring it was wrong in a way worth
recording: the crates.io API download URL returned **0 bytes**, and grepping that emptiness produced
"0 hits" — indistinguishable from a real negative. The re-run against `static.crates.io` fetched
27,698 bytes and produced a genuine zero. Third false zero of the day; absence keeps looking like
thoroughness.

Consequence: today's work cannot be published as 2.3.0. That number is taken and means something
else. It needs 2.3.1 or 2.4.0 — a deliberate release decision, never a side effect of a build.

## Version numbers run BACKWARDS against time across machines

    this machine   2.2.0   17 May
    .109           1.0.2    4 Aug
    .80            1.0.0    1 May

The higher number is nearly three months older. So *"is that box up to date"* cannot be answered by
comparing version strings, and a reader who trusts `2.2.0 > 1.0.2` reaches the opposite of the
truth. This sharpens the `no global version` rule: it is not only that up-to-date is a claim about a
chosen unit — **the ordering itself does not survive the comparison.**

## The binding still has no verb, measured a third way

`crates/tbz-cli/src/` contains **zero** references to `producer_identity`, `archive_id`,
`verify_producer` or `verify_signature_in_archive`. The freshly built 2.3.0 binary carries
`producer_identity` twice — as serde field names, because manifests round-trip through the struct —
and carries the domain separators `tbz-archive-id` / `tbz-producer-archive` **zero** times, because
nothing calls the functions that use them.

The binding rides along in the data and is verified by no invocable surface. `tbz verify` and
`tbz inspect` cannot report it. Same defect as `tibet_mux.verify_forward_consent` this morning, and
it is why ceremony slice B (*verdict from the bytes*) is blocked: the only tool that can read those
bindings does not expose them.

## And a fourth, which was mine

The first build reported success and built nothing:

    cargo build --release -p tbz-cli   ->  error: package ID specification `tbz-cli` did not match

The directory is `crates/tbz-cli`; the package is `tibet-zip-cli`. The command failed — and the run
reported **exit 0**, because it piped through `tail`, so the status measured was `tail`'s. A
pipeline had silently replaced the thing under test with something that always succeeds. Rebuilt
without the pipe, checking `$?` directly: exit 0, 23.41 s, 2.3.0.

Same family as everything above: a green signal that measured nothing.

## Next

- a new version number before any publish (2.3.1 / 2.4.0), deliberately chosen
- `tbz inspect` / `tbz verify` must surface the binding, or nothing downstream can consume it
- `oomllama` vs `tibet-oomllama`: pick the canonical name
- node inventory (`.109` 1.0.2, `.80` 1.0.0) is a separate reconciliation, and the version strings
  there cannot be trusted to order themselves
