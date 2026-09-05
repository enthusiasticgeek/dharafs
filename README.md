# dharafs

Kernel-agnostic, log-structured, append-only filesystem for the [vāṇी compiler](https://github.com/enthusiasticgeek/vani-compiler).

Extracted from [Dhruva OS](https://github.com/enthusiasticgeek/dhruvaos), where this same logic
has run under extensive regression testing (real-hardware-shaped SD card round trips, a
70/70 simulated-power-loss torn-write sweep, ASAN/UBSAN-clean host-process runs) across many
rounds of development.

## Add to your project

```toml
# vani.toml
[deps]
dharafs = { registry = "kosh", version = "^0.1" }
```

```sh
vanic add dharafs
vanic build
```

`vanic add` resolves to `src/lib.vani` (Tier 1, below) by default. Want real media
encryption and/or verified I/O built in? See "Choosing an entry point" below — those are a
different file within this same package, not a different dependency.

## Architecture: one core, composable entry points

The actual filesystem logic lives in `src/core.vani` and is never duplicated. Everything
else -- media encryption, verified I/O -- is a separate file that adds to it. An *entry
point* is just a small file that `use`s the pieces you want:

| Entry point | Core FS | Media encryption | Verified I/O |
|---|:---:|:---:|:---:|
| `src/lib.vani` (Tier 1, default) | Yes | consumer-provided hook | No |
| `src/lib_encrypted.vani` | Yes | **built in** | No |
| `src/lib_verified.vani` | Yes | consumer-provided hook | **built in** |
| `src/lib_tier2.vani` (Tier 2, full) | Yes | **built in** | **built in** |

This is possible because vāṇी resolves function names globally, flat, at compile time: a
real `fn` body and an `extern "C" fn` declaration of the same name can't coexist in one
compiled program. `core.vani` therefore never declares the three media-encryption hook
functions itself -- whichever entry point you `use` completes that decision for you, which
is what makes all four combinations buildable from the same unmodified core.

## What you get (all entry points)

Fixed 512-byte records, raw block numbers, a checksum + monotonic sequence number per
record, log-structured (every write appends; nothing is ever modified in place):

| Area | Functions |
|---|---|
| Core I/O | `dharafs_init`, `dharafs_append`, `dharafs_read`, `dharafs_write_raw_checked`, `dharafs_delete`, `dharafs_rename` |
| Metadata | `dharafs_stat`, `dharafs_chmod`, `dharafs_chown`, permission checks (owner/group/other, root bypass) |
| Directories | `dharafs_list_dir`, `dharafs_list` (prefix query) |
| Directory index | A hashed, O(1)-lookup accelerator over the log (`dirindex_*`) — a miss just falls back to the same full log scan the code always did, so it's included unconditionally rather than being an optional feature |
| Snapshots | `dharafs_snapshot_create`, `_delete`, `_read` — pin a sequence number and read the filesystem as of that point |
| Transactions | Append-only semantics make every write crash-atomic: a torn write during append leaves the previous version intact, never a half-written one |

## What this package does NOT include, on purpose

- **The FS request queue** (`dharafs_queue_*`) — a priority-aware queue built on scheduler
  primitives (`current_eff_prio`, `current_task_get`). Real OS-scheduler dependency, stays in
  Dhruva OS.
- **Any bespoke crypto beyond ChaCha20-Poly1305/SHA-256/HMAC/PBKDF2** — no AES, no TLS. Those
  four primitives (`src/crypto.vani`) are what media encryption and verified I/O are actually
  built on; anything beyond that is a separate, independent add-on this package doesn't need.

## Tier 2: media encryption and verified I/O

**Media encryption** (`src/media_crypto.vani`, real ChaCha20-Poly1305 AEAD, ported from
Dhruva OS's own round-69 implementation) is hooked in at `dharafs_block_read`/
`dharafs_block_write` -- the one choke point every physical block read/write already passes
through -- so every higher FS layer (checksums, journaling, permissions, dirindex,
snapshots) keeps operating on plaintext; only the bytes that actually reach
`dharafs_backend_read_block`/`_write_block` are ciphertext. Off by default. Real tamper
detection (a corrupted on-disk block or tag is rejected, not silently decrypted into
garbage) and no two-time-pad weakness (a per-block write-counter, persisted alongside the
tag, guarantees the same block written twice never reuses a keystream).

```
let init_status: i64 = dharafs_init();
let key_status: i64 = dharafs_crypto_key_init("your passphrase here", "a salt", 20000);
let _ = dharafs_crypto_set_enabled(1 as u32);
// every dharafs_append/read/dharafs_block_write/read call is now encrypted at rest
```

`dharafs_crypto_key_init(passphrase, salt, iterations)` derives the key via
PBKDF2-HMAC-SHA256 -- unlike Dhruva OS's own kernel (which hardcodes one fixed
passphrase/salt, an honest limitation of a project with no hardware key store), this
package leaves that choice to you: where the passphrase comes from is your call.
`encrypt_block`/`decrypt_block` both fail closed (return `-2`) if you enable encryption
without ever calling `dharafs_crypto_key_init` first, rather than silently encrypting with
an all-zero key.

**Verified I/O** (`src/verified_io.vani`, ported from Dhruva OS's own round-48
implementation) adds `dharafs_write_verified`/`dharafs_read_verified`: a SHA-256 digest of
the file's data is written alongside it (at `path + ".sha256"`, no on-disk record format
change), and re-checked on every verified read. `dharafs_read_verified` returns `-3` if the
data doesn't match its digest -- tamper or corruption beyond what the per-record checksum
alone catches. Composes with media encryption with no special handling needed: the digest
covers plaintext, exactly like every other core.vani function already sees plaintext
regardless of whether encryption is on.

### Choosing an entry point

```
use "dharafs/src/lib_tier2.vani";   // full Tier 2: both features built in
use "dharafs/src/lib_encrypted.vani"; // media encryption only
use "dharafs/src/lib_verified.vani";  // verified I/O only
```

## What you must provide

Six `extern "C" fn` declarations regardless of entry point (block I/O, allocator, logging)
-- see the table below. `src/lib.vani`/`src/lib_verified.vani` additionally need a
three-function media-encryption hook (stubbable to always-off, see `test/host_stubs_tier1_crypto_stub.c`);
`src/lib_encrypted.vani`/`src/lib_tier2.vani` implement that hook for real instead, so you
don't provide it. Everything else (roughly 90 mechanical scratch-buffer and fixed-size-table
accessors) ships as ready-to-link reference implementations in `runtime/`; compile and link
the files your chosen entry point needs rather than reimplementing this layer.

| Function | Purpose |
|---|---|
| `dharafs_backend_read_block(block_num, buf) -> i64` | Read one 512-byte block. 0 = success. |
| `dharafs_backend_write_block(block_num, buf) -> i64` | Write one 512-byte block. 0 = success. |
| `dharafs_alloc_bytes(n) -> mut ref i64` | Allocate `n` zeroed bytes. Never freed — this is a bump allocator by design (see `test/host_stubs.c` for a `calloc`-backed example). |
| `dharafs_log_puts(s: Str) -> i64` | Write a string to your log sink. |
| `dharafs_log_putc(c: i64) -> i64` | Write one character to your log sink. |
| `dharafs_log_put_hex32(v: u32) -> i64` | Write a `u32` as 8 hex digits to your log sink. |

Tier 1 / `lib_verified.vani` only:

| Function | Purpose |
|---|---|
| `dharafs_crypto_get_enabled() -> u32` | Return `1` to enable the media-encryption hook, `0` to disable it. A stub always returning `0` is fine if you don't want this feature — `encrypt_block`/`decrypt_block` then never get called. |
| `dharafs_crypto_encrypt_block(block_num, plaintext, out_ciphertext) -> i64` | Encrypt one block before it's written. Only called if the hook above is enabled. |
| `dharafs_crypto_decrypt_block(block_num, ciphertext, out_plaintext) -> i64` | Decrypt one block after it's read. Only called if the hook above is enabled. |

### Runtime files by entry point

| Entry point | Link these `runtime/*.c` files |
|---|---|
| `src/lib.vani` | `dharafs_runtime.c` |
| `src/lib_encrypted.vani` | `dharafs_runtime.c`, `dharafs_crypto_runtime.c`, `dharafs_media_crypto_runtime.c` |
| `src/lib_verified.vani` | `dharafs_runtime.c`, `dharafs_crypto_runtime.c`, `dharafs_verified_io_runtime.c` |
| `src/lib_tier2.vani` | `dharafs_runtime.c`, `dharafs_crypto_runtime.c`, `dharafs_media_crypto_runtime.c`, `dharafs_verified_io_runtime.c` |

Plus your own six (or nine, for Tier 1/`lib_verified.vani`) consumer-provided functions --
see `test/host_stubs.c` (the six always-needed ones) and
`test/host_stubs_tier1_crypto_stub.c` (the three Tier-1-only hook stubs) for a complete,
working example of each.

## Testing

```sh
# Tier 1
vanic run test/host_test.vani --backend=c \
  --link-with runtime/dharafs_runtime.c \
  --link-with test/host_stubs.c \
  --link-with test/host_stubs_tier1_crypto_stub.c

# Tier 2 (media encryption + verified I/O)
vanic run test/host_test_tier2.vani --backend=c \
  --link-with runtime/dharafs_runtime.c \
  --link-with runtime/dharafs_crypto_runtime.c \
  --link-with runtime/dharafs_media_crypto_runtime.c \
  --link-with runtime/dharafs_verified_io_runtime.c \
  --link-with test/host_stubs.c
```

`test/host_test.vani` runs a real standalone round trip (init, append, read, overwrite,
rename, delete) against an in-memory disk. `test/host_test_tier2.vani` additionally runs:
SHA-256/HMAC-SHA256/PBKDF2-HMAC-SHA256 known-answer tests (verified against Python's
`hashlib`/`hmac`) and a ChaCha20-Poly1305 AEAD known-answer test (verified against the real
`cryptography` library) with tag- and ciphertext-tamper rejection checks; a real media
encryption round trip including the two-time-pad fix and tamper detection; a full
`dharafs_block_write`/`dharafs_read` integration test proving on-disk bytes are real
ciphertext while the higher-level API stays transparent; a verified-I/O round trip with tamper
detection; and a combined media-encryption + verified-I/O composition test. Both suites have
zero dependency on any Dhruva OS kernel code, and both have been verified clean under
AddressSanitizer/UndefinedBehaviorSanitizer (the only sanitizer findings are expected
one-time startup allocations from the bump allocator, not leaks in a repeated code path —
see `test/host_stubs.c`'s own comment).

## License

Apache License 2.0 — see `LICENSE` and `NOTICE`.
