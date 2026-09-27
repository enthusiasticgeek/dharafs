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
encryption, verified I/O, and/or the FS request queue built in? See "Choosing an entry
point" below — those are a different file within this same package, not a different
dependency.

## Architecture: one core, composable entry points

The actual filesystem logic lives in `src/core.vani` and is never duplicated. Everything
else -- media encryption, verified I/O, the FS request queue -- is a separate file that adds
to it. An *entry point* is just a small file that `use`s the pieces you want:

| Entry point | Core FS | Media encryption | Verified I/O | FS request queue |
|---|:---:|:---:|:---:|:---:|
| `src/lib.vani` (Tier 1, default) | Yes | consumer-provided hook | No | No |
| `src/lib_encrypted.vani` | Yes | **built in** | No | No |
| `src/lib_verified.vani` | Yes | consumer-provided hook | **built in** | No |
| `src/lib_queued.vani` | Yes | consumer-provided hook | No | **built in** |
| `src/lib_tier2.vani` (Tier 2) | Yes | **built in** | **built in** | No |
| `src/lib_tier3.vani` (Tier 3, full) | Yes | **built in** | **built in** | **built in** |

This is possible because vāṇी resolves function names globally, flat, at compile time: a
real `fn` body and an `extern "C" fn` declaration of the same name can't coexist in one
compiled program. `core.vani` therefore never declares the three media-encryption hook
functions itself -- whichever entry point you `use` completes that decision for you, which
is what makes all six combinations buildable from the same unmodified core. Want a
combination not listed (say, encryption + the queue, no verified I/O)? Write your own 4-line
entry point following the same pattern as the ones in `src/` -- that's the point of this
architecture, not a gap in it.

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

## Tier 3: the priority-aware FS request queue

Every `dharafs_*` call runs synchronously, inline, in whatever task called it -- there's no
way for a higher-priority task's write to jump ahead of a lower-priority one's. `src/fsqueue.vani`
(ported from Dhruva OS's own implementation) adds an opt-in, bounded (8-slot) queue on top:

```
let slot: i64 = dharafs_queue_submit("log.txt", "some data");  // enqueues, doesn't write yet
let result: i64 = dharafs_queue_dispatch_one();  // processes the single highest-priority pending request
```

`dharafs_queue_dispatch_one` picks the numerically lowest priority value (this project's "0 is
highest" convention), oldest submission breaking ties (FIFO fairness, not an arbitrary tie
order), and runs it through the exact same `dharafs_append_raw`/`dharafs_delete_raw` every
synchronous call already uses -- same crash-consistency guarantees, same dirindex
integration. Draining the queue (calling `dispatch_one` repeatedly until it returns `-1`)
from a dedicated background task is entirely your own responsibility -- this package has no
scheduler to run one on.

This is the one feature with a genuine, unavoidable dependency on your kernel's scheduler:
`dharafs_queue_submit` (the convenience wrapper above) tags each request with the calling
task's own `current_eff_prio()`/`current_task_get()`. There's no portable default for "what
is this task's priority" the way there was for encryption (which could default to off) --
but if you don't have a real multi-priority scheduler, stubbing both to a fixed value (see
`test/host_stubs_scheduler_stub.c`) is a fine, honest degradation: the queue still works
correctly, every request just ties on priority and falls back to pure FIFO order. Every
*other* function in `fsqueue.vani` (`dharafs_queue_submit_write_raw`/`_submit_delete_raw`
take priority/task_id as explicit parameters) has zero scheduler dependency at all.

`dharafs_queue_dispatch_one` calls `dharafs_append_raw`/`_delete_raw` directly, not the
verified-I/O variants -- a queue-dispatched write does not get a verified-I/O digest. This
is a real, by-design boundary matching Dhruva OS's own upstream interface exactly, not a gap
introduced by this extraction.

### Choosing an entry point

```
use "dharafs/src/lib_tier3.vani";     // everything: encryption + verified I/O + the queue
use "dharafs/src/lib_tier2.vani";     // encryption + verified I/O, no queue
use "dharafs/src/lib_encrypted.vani"; // media encryption only
use "dharafs/src/lib_verified.vani";  // verified I/O only
use "dharafs/src/lib_queued.vani";    // the FS request queue only
```

## What you must provide

Six `extern "C" fn` declarations regardless of entry point (block I/O, allocator, logging)
-- see the table below. Two more groups are conditional on which optional features your
entry point includes:

| Function | Purpose |
|---|---|
| `dharafs_backend_read_block(block_num, buf) -> i64` | Read one 512-byte block. 0 = success. |
| `dharafs_backend_write_block(block_num, buf) -> i64` | Write one 512-byte block. 0 = success. |
| `dharafs_alloc_bytes(n) -> mut ref i64` | Allocate `n` zeroed bytes. Never freed — this is a bump allocator by design (see `test/host_stubs.c` for a `calloc`-backed example). |
| `dharafs_log_puts(s: Str) -> i64` | Write a string to your log sink. |
| `dharafs_log_putc(c: i64) -> i64` | Write one character to your log sink. |
| `dharafs_log_put_hex32(v: u32) -> i64` | Write a `u32` as 8 hex digits to your log sink. |

`src/lib.vani` / `src/lib_verified.vani` / `src/lib_queued.vani` only (the other three
implement this hook for real instead, so you don't provide it -- see
`test/host_stubs_tier1_crypto_stub.c` for a working always-off stub):

| Function | Purpose |
|---|---|
| `dharafs_crypto_get_enabled() -> u32` | Return `1` to enable the media-encryption hook, `0` to disable it. A stub always returning `0` is fine if you don't want this feature — `encrypt_block`/`decrypt_block` then never get called. |
| `dharafs_crypto_encrypt_block(block_num, plaintext, out_ciphertext) -> i64` | Encrypt one block before it's written. Only called if the hook above is enabled. |
| `dharafs_crypto_decrypt_block(block_num, ciphertext, out_plaintext) -> i64` | Decrypt one block after it's read. Only called if the hook above is enabled. |

`src/lib_queued.vani` / `src/lib_tier3.vani` only (see
`test/host_stubs_scheduler_stub.c` for a fixed-value stub if you have no real per-task
priority concept):

| Function | Purpose |
|---|---|
| `current_eff_prio() -> u32` | The calling task's own effective scheduling priority (0 = highest). Only called from `dharafs_queue_submit`. |
| `current_task_get() -> u32` | The calling task's own ID. Only called from `dharafs_queue_submit`. |

### Runtime files by entry point

| Entry point | Link these `runtime/*.c` files |
|---|---|
| `src/lib.vani` | `dharafs_runtime.c` |
| `src/lib_encrypted.vani` | `dharafs_runtime.c`, `dharafs_crypto_runtime.c`, `dharafs_media_crypto_runtime.c` |
| `src/lib_verified.vani` | `dharafs_runtime.c`, `dharafs_crypto_runtime.c`, `dharafs_verified_io_runtime.c` |
| `src/lib_queued.vani` | `dharafs_runtime.c`, `dharafs_fsqueue_runtime.c` |
| `src/lib_tier2.vani` | `dharafs_runtime.c`, `dharafs_crypto_runtime.c`, `dharafs_media_crypto_runtime.c`, `dharafs_verified_io_runtime.c` |
| `src/lib_tier3.vani` | all five `runtime/*.c` files above |

Plus your own consumer-provided functions for whichever conditional groups above your entry
point needs -- `test/host_stubs.c` (the six always-needed ones),
`test/host_stubs_tier1_crypto_stub.c` (the three Tier-1-style hook stubs), and
`test/host_stubs_scheduler_stub.c` (the two queue-only scheduler stubs) are complete, working
examples of each.

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

# The FS request queue, in isolation
vanic run test/host_test_fsqueue.vani --backend=c \
  --link-with runtime/dharafs_runtime.c \
  --link-with runtime/dharafs_fsqueue_runtime.c \
  --link-with test/host_stubs.c \
  --link-with test/host_stubs_tier1_crypto_stub.c \
  --link-with test/host_stubs_scheduler_stub.c

# Tier 3 (everything together -- a composition smoke test, not a
# re-verification of each feature; see the two suites above for that)
vanic run test/host_test_tier3.vani --backend=c \
  --link-with runtime/dharafs_runtime.c \
  --link-with runtime/dharafs_crypto_runtime.c \
  --link-with runtime/dharafs_media_crypto_runtime.c \
  --link-with runtime/dharafs_verified_io_runtime.c \
  --link-with runtime/dharafs_fsqueue_runtime.c \
  --link-with test/host_stubs.c \
  --link-with test/host_stubs_scheduler_stub.c
```

`test/host_test.vani` runs a real standalone round trip (init, append, read, overwrite,
rename, delete) against an in-memory disk. `test/host_test_tier2.vani` additionally runs:
SHA-256/HMAC-SHA256/PBKDF2-HMAC-SHA256 known-answer tests (verified against Python's
`hashlib`/`hmac`) and a ChaCha20-Poly1305 AEAD known-answer test (verified against the real
`cryptography` library) with tag- and ciphertext-tamper rejection checks; a real media
encryption round trip including the two-time-pad fix and tamper detection; a full
`dharafs_block_write`/`dharafs_read` integration test proving on-disk bytes are real
ciphertext while the higher-level API stays transparent; a verified-I/O round trip with tamper
detection; and a combined media-encryption + verified-I/O composition test. `test/host_test_fsqueue.vani`
covers priority ordering with FIFO tie-breaking (four requests submitted out of priority
order, dispatched one at a time, each checked against the live filesystem to confirm the
exact dispatch order), full-queue rejection, oversized-path/data/negative-length rejection,
delete-via-queue, and the one scheduler-dependent function (`dharafs_queue_submit`) against a
fixed stub. `test/host_test_tier3.vani` confirms all three additions link and run together
with zero conflict, including one real cross-feature check: a write dispatched through the
queue is transparently encrypted at rest, exactly like a direct `dharafs_append` call.

All four suites have zero dependency on any Dhruva OS kernel code, and all four have been
verified clean under AddressSanitizer/UndefinedBehaviorSanitizer (the only sanitizer findings
are expected one-time startup allocations from the bump allocator, not leaks in a repeated
code path — see `test/host_stubs.c`'s own comment).

### Static scratch-buffer bounds audit

```sh
python3 test/scratch_bounds_audit.py
```

DharaFS has no hand-written assembly, so `buf_read_byte`/`buf_write_byte`/`buf_read_u32`/
`buf_write_u32`/`buf_checksum` (declared in `src/buf_primitives.vani`, implemented in
`runtime/dharafs_runtime.c`) give vani code entirely unchecked raw pointer+offset access
into the fixed-size C scratch buffers `runtime/*.c` allocates via `SCRATCH_BUF`/
`SCRATCH_BUF_PTR` — by design, matching the semantics of the upstream assembly this logic
was ported from. `test/scratch_bounds_audit.py` statically catches the resulting bug class:
a vani-side offset expression that can exceed a buffer's real C-side capacity, silently
corrupting whatever static data sits next in memory. It flags (1) a literal offset that
unconditionally overruns a buffer (DEFINITE) and (2) an offset derived from a `while VAR <
BOUND` loop's own induction variable that overruns at the loop's maximum reachable value
(REVIEW). It only resolves call sites that pass a buffer accessor (e.g.
`sha256_h_scratch_get()`) directly as the first argument — call sites that receive the
buffer through a function parameter are a documented, open gap (see the tool's own header
comment). Current state: 0 DEFINITE, 0 REVIEW.

## License

Apache License 2.0 — see `LICENSE` and `NOTICE`.
