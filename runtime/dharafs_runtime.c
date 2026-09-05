/* DharaFS portable runtime: plain, hosted-independent C implementations
 * of every extern "C" fn src/lib.vani calls that is PURELY mechanical --
 * raw buffer accessors, fixed-size scratch buffers, and the small
 * fixed-capacity state/dirindex/snapshot tables. None of this touches
 * real hardware or an OS, so one reference implementation can ship here
 * instead of every consumer reimplementing it.
 *
 * Deliberately NOT implemented here (see src/lib.vani's own header
 * comment and README.md for the full contract) -- these are the real,
 * environment-specific seams every consumer must provide themselves:
 *   - dharafs_backend_read_block / dharafs_backend_write_block (block I/O)
 *   - dharafs_alloc_bytes (allocator)
 *   - dharafs_log_puts / dharafs_log_putc / dharafs_log_put_hex32 (logging)
 *   - dharafs_crypto_get_enabled / _encrypt_block / _decrypt_block
 *     (optional media-encryption hook)
 *
 * Buffer sizes below are copied EXACTLY from Dhruva OS's own boot
 * sequence (kernel_main.vani's dharafs_*_scratch_set(dhruva_alloc_bytes(N))
 * calls and boot/media_crypto_state.S's .space directives) -- this is
 * the same sizing this logic has run against under extensive real
 * regression testing upstream, not a fresh guess.
 */
#include <stdint.h>
#include <string.h>

/* ---- Raw buffer accessors (byte-for-byte match of the upstream
 * boot/dharafs_buf.S semantics: buf is a plain byte pointer, offset is
 * a plain byte offset, no bounds checking -- callers are trusted to
 * stay within the scratch buffer they were handed). */

uint32_t buf_write_byte(int64_t *buf, uint32_t offset, uint32_t value) {
    unsigned char *p = (unsigned char *)buf;
    p[offset] = (unsigned char)value;
    return 0;
}

uint32_t buf_read_byte(int64_t *buf, uint32_t offset) {
    unsigned char *p = (unsigned char *)buf;
    return (uint32_t)p[offset];
}

uint32_t buf_write_u32(int64_t *buf, uint32_t offset, uint32_t value) {
    unsigned char *p = (unsigned char *)buf + offset;
    memcpy(p, &value, 4);
    return 0;
}

uint32_t buf_read_u32(int64_t *buf, uint32_t offset) {
    unsigned char *p = (unsigned char *)buf + offset;
    uint32_t v;
    memcpy(&v, p, 4);
    return v;
}

/* Rotate-left-by-1-then-add mix, matching the upstream ARM `ror #31`
 * (rotate RIGHT by 31 of a 32-bit value == rotate LEFT by 1). */
uint32_t buf_checksum(int64_t *buf, uint32_t start_offset, uint32_t byte_len) {
    unsigned char *p = (unsigned char *)buf;
    uint32_t csum = 0;
    uint32_t end = start_offset + byte_len;
    for (uint32_t i = start_offset; i < end; i++) {
        csum = ((csum << 1) | (csum >> 31)) + (uint32_t)p[i];
    }
    return csum;
}

/* ---- Self-test helpers (used by dharafs's own internal round-trip
 * self-check function). */

int64_t test_fill_pattern(int64_t *buf, int64_t byte_count) {
    unsigned char *p = (unsigned char *)buf;
    for (int64_t i = 0; i < byte_count; i++) {
        p[i] = (unsigned char)(i & 0xff);
    }
    return 0;
}

int64_t test_compare_buffers(int64_t *a, int64_t *b, int64_t byte_count) {
    return memcmp(a, b, (size_t)byte_count) == 0 ? 0 : 1;
}

/* ---- Fixed-size scratch buffers. Sizes match upstream exactly. */

#define SCRATCH_BUF(NAME, SIZE)                                \
    static int64_t NAME##_storage[((SIZE) + 7) / 8];           \
    int64_t *NAME##_get(void) { return NAME##_storage; }

/* dharafs_crypto_scratch is named "_ptr" not "_get" upstream (it comes
 * from boot/media_crypto_state.S's own fixed-address label, not the
 * uniform NAME_get/NAME_set scratch-accessor shape every other buffer
 * here uses), so it needs its own accessor rather than the macro. */
#define SCRATCH_BUF_PTR(NAME, SIZE)                            \
    static int64_t NAME##_storage[((SIZE) + 7) / 8];           \
    int64_t *NAME##_ptr(void) { return NAME##_storage; }

SCRATCH_BUF(dharafs_sd_scratch, 512)
SCRATCH_BUF(dharafs_path_scratch, 32)
SCRATCH_BUF(dharafs_data_scratch, 4096)
SCRATCH_BUF(dharafs_stat_scratch, 12)
SCRATCH_BUF(dharafs_dir_scratch, 32)
SCRATCH_BUF(dharafs_log_path_scratch, 32)
SCRATCH_BUF(dharafs_log_header_path_scratch, 32)
SCRATCH_BUF(dharafs_log_header_data_scratch, 8)
SCRATCH_BUF(dharafs_log_existing_scratch, 4096)
SCRATCH_BUF(dharafs_log_combined_scratch, 4096)
SCRATCH_BUF(dharafs_appendonly_check_scratch, 4096)
SCRATCH_BUF(dharafs_rename_new_path_scratch, 32)
SCRATCH_BUF_PTR(dharafs_crypto_scratch, 512)

/* ---- Core filesystem state: next_block/next_seq/log_start, the
 * currently-active uid/gid, a running commit counter. */

static uint32_t g_next_block = 0;
static uint32_t g_next_seq = 0;
static uint32_t g_log_start = 0;
static uint32_t g_uid = 0;
static uint32_t g_gid = 0;
static uint32_t g_commit_count = 0;

uint32_t dharafs_state_get_next_block(void) { return g_next_block; }
uint32_t dharafs_state_get_next_seq(void) { return g_next_seq; }
uint32_t dharafs_state_get_log_start(void) { return g_log_start; }

uint32_t dharafs_state_set(uint32_t next_block, uint32_t next_seq) {
    g_next_block = next_block;
    g_next_seq = next_seq;
    return 0;
}

uint32_t dharafs_state_set_log_start(uint32_t log_start) {
    g_log_start = log_start;
    return 0;
}

uint32_t dharafs_user_get_uid(void) { return g_uid; }
uint32_t dharafs_user_get_gid(void) { return g_gid; }

uint32_t dharafs_user_set(uint32_t uid, uint32_t gid) {
    g_uid = uid;
    g_gid = gid;
    return 0;
}

uint32_t dharafs_commit_count_increment(void) {
    g_commit_count += 1;
    return g_commit_count;
}

uint32_t dharafs_commit_count_get(void) { return g_commit_count; }

/* ---- Hashed directory index: 256 fixed slots, up to 32 path bytes
 * each. A miss (or an out-of-range index -- can't happen from lib.vani
 * itself, since dirindex_max_slots()==256 bounds every caller, but the
 * `% 256` here matches upstream's own defensive wraparound rather than
 * trusting that invariant blindly) just means "index unknown", and
 * dharafs_find_latest_block_raw's own linear-scan fallback handles
 * that correctly -- see src/lib.vani's header comment. */

static int64_t g_dirindex_valid[256];
static int64_t g_dirindex_hash[256];
static int64_t g_dirindex_pathlen[256];
static int64_t g_dirindex_block[256];
static uint8_t g_dirindex_path_bytes[256 * 32];

int64_t dirindex_get_valid_at(uint32_t i) { return g_dirindex_valid[i % 256]; }
int64_t dirindex_set_valid_at(uint32_t i, uint32_t v) { g_dirindex_valid[i % 256] = v; return 0; }
int64_t dirindex_get_hash_at(uint32_t i) { return g_dirindex_hash[i % 256]; }
int64_t dirindex_set_hash_at(uint32_t i, uint32_t v) { g_dirindex_hash[i % 256] = v; return 0; }
int64_t dirindex_get_pathlen_at(uint32_t i) { return g_dirindex_pathlen[i % 256]; }
int64_t dirindex_set_pathlen_at(uint32_t i, uint32_t v) { g_dirindex_pathlen[i % 256] = v; return 0; }
int64_t dirindex_get_block_at(uint32_t i) { return g_dirindex_block[i % 256]; }
int64_t dirindex_set_block_at(uint32_t i, uint32_t v) { g_dirindex_block[i % 256] = v; return 0; }
int64_t dirindex_get_path_byte(uint32_t combined_index) { return g_dirindex_path_bytes[combined_index % (256 * 32)]; }
int64_t dirindex_set_path_byte(uint32_t combined_index, uint32_t v) { g_dirindex_path_bytes[combined_index % (256 * 32)] = (uint8_t)v; return 0; }

/* ---- Snapshots / versioned rollback: 8 fixed slots, up to 32 name
 * bytes each. */

static int64_t g_snapshot_valid[8];
static int64_t g_snapshot_pinned_seq[8];
static int64_t g_snapshot_name_len[8];
static uint8_t g_snapshot_name_bytes[8 * 32];

int64_t snapshot_valid_get_at(uint32_t i) { return g_snapshot_valid[i % 8]; }
int64_t snapshot_valid_set_at(uint32_t i, uint32_t v) { g_snapshot_valid[i % 8] = v; return 0; }
int64_t snapshot_pinned_seq_get_at(uint32_t i) { return g_snapshot_pinned_seq[i % 8]; }
int64_t snapshot_pinned_seq_set_at(uint32_t i, uint32_t v) { g_snapshot_pinned_seq[i % 8] = v; return 0; }
int64_t snapshot_name_len_get_at(uint32_t i) { return g_snapshot_name_len[i % 8]; }
int64_t snapshot_name_len_set_at(uint32_t i, uint32_t v) { g_snapshot_name_len[i % 8] = v; return 0; }
int64_t snapshot_get_name_byte(uint32_t combined_index) { return g_snapshot_name_bytes[combined_index % (8 * 32)]; }
int64_t snapshot_set_name_byte(uint32_t combined_index, uint32_t v) { g_snapshot_name_bytes[combined_index % (8 * 32)] = (uint8_t)v; return 0; }
