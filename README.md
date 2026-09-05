# dharafs

Kernel-agnostic, log-structured, append-only filesystem for the [vāṇी compiler](https://github.com/enthusiasticgeek/vani-compiler).

Extracted from [Dhruva OS](https://github.com/enthusiasticgeek/dhruvaos), where this same logic
has run under extensive regression testing (real-hardware-shaped SD card round trips, a
70/70 simulated-power-loss torn-write sweep, ASAN/UBSAN-clean host-process runs) across many
rounds of development. This package is that filesystem's "Tier 1" core: every `dharafs_*`
function except the priority-aware FS request queue (`dharafs_queue_*`), which has a genuine
scheduler dependency and stays in Dhruva OS itself.

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

## What you get

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
- **Any cipher implementation.** The media-encryption hook below is a real extension point,
  but AES/ChaCha20/SHA-256/etc. are a separate, optional add-on a consumer plugs in — not a
  hard dependency of the filesystem itself.
- **SHA-256-hash-verified companion-file I/O** (`dharafs_write_verified_*` /
  `dharafs_read_verified_*`) — depends on the excluded crypto tier for the same reason.

## What you must provide

Nine `extern "C" fn` declarations — the genuinely environment-specific seams. Everything
else (roughly 80 mechanical scratch-buffer and fixed-size-table accessors) ships as a
ready-to-link reference implementation in `runtime/dharafs_runtime.c`; most consumers should
just compile and link that file rather than reimplementing this layer.

| Function | Purpose |
|---|---|
| `dharafs_backend_read_block(block_num, buf) -> i64` | Read one 512-byte block. 0 = success. |
| `dharafs_backend_write_block(block_num, buf) -> i64` | Write one 512-byte block. 0 = success. |
| `dharafs_alloc_bytes(n) -> mut ref i64` | Allocate `n` zeroed bytes. Never freed — this is a bump allocator by design (see `test/host_stubs.c` for a `calloc`-backed example). |
| `dharafs_log_puts(s: Str) -> i64` | Write a string to your log sink. |
| `dharafs_log_putc(c: i64) -> i64` | Write one character to your log sink. |
| `dharafs_log_put_hex32(v: u32) -> i64` | Write a `u32` as 8 hex digits to your log sink. |
| `dharafs_crypto_get_enabled() -> u32` | Return `1` to enable the media-encryption hook, `0` to disable it. A stub always returning `0` is fine if you don't want this feature — `encrypt_block`/`decrypt_block` then never get called. |
| `dharafs_crypto_encrypt_block(block_num, plaintext, out_ciphertext) -> i64` | Encrypt one block before it's written. Only called if the hook above is enabled. |
| `dharafs_crypto_decrypt_block(block_num, ciphertext, out_plaintext) -> i64` | Decrypt one block after it's read. Only called if the hook above is enabled. |

See `test/host_stubs.c` for a complete, working example of all nine (an in-memory disk, a
`calloc`-backed allocator, `stdout` logging, and an always-off crypto stub).

## Testing

```sh
vanic run test/host_test.vani --backend=c \
  --link-with runtime/dharafs_runtime.c --link-with test/host_stubs.c
```

This runs a real standalone round trip (init, append, read, overwrite, rename, delete)
against an in-memory disk, with zero dependency on any Dhruva OS kernel code. It has also
been verified clean under AddressSanitizer/UndefinedBehaviorSanitizer (the only sanitizer
findings are two expected one-time startup allocations from the bump allocator, not leaks in
a repeated code path — see `test/host_stubs.c`'s own comment).

## License

Apache License 2.0 — see `LICENSE` and `NOTICE`.
