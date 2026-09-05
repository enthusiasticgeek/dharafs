/* Host test harness: implements the environment-specific seams every
 * entry point (Tier 1's src/lib.vani AND Tier 2's src/lib_tier2.vani)
 * needs regardless of tier -- block I/O, the allocator, logging.
 * Everything mechanical (buffer/scratch/dirindex/snapshot accessors)
 * is provided by runtime/dharafs_runtime.c and is NOT reimplemented
 * here.
 *
 * Deliberately does NOT implement the media-encryption hook
 * (dharafs_crypto_get_enabled/_encrypt_block/_decrypt_block): Tier 1
 * needs a consumer-provided stub for these (see
 * test/host_stubs_tier1_crypto_stub.c, linked ONLY by Tier 1's own
 * test), while Tier 2 provides a real implementation of the same
 * three names via runtime/dharafs_media_crypto_runtime.c -- the two
 * are mutually exclusive by design (see src/core.vani's own header
 * comment), so this shared file must stay out of that choice
 * entirely rather than picking one and silently breaking the other
 * tier's test.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- Block I/O: an in-memory "disk" standing in for a real backend. */

/* 4224: covers dharafs_init's 0..2047 log-region scan plus Tier 2's
 * media-encryption metadata region (blocks 4000+, one 32-byte entry
 * per tracked data block, 16 packed per 512-byte sector -- needs at
 * least 4000 + 2048/16 = 4128 blocks; raised with margin), even though
 * Tier 1 alone never touches anything past ~2048. */
#define HOST_DISK_BLOCKS 4224
#define HOST_DISK_BLOCK_BYTES 512
static unsigned char g_virtual_disk[HOST_DISK_BLOCKS * HOST_DISK_BLOCK_BYTES];

int64_t dharafs_backend_read_block(int64_t block_num, int64_t *buf) {
    if (block_num < 0 || block_num >= HOST_DISK_BLOCKS) {
        return -1;
    }
    memcpy(buf, g_virtual_disk + (size_t)block_num * HOST_DISK_BLOCK_BYTES,
           HOST_DISK_BLOCK_BYTES);
    return 0;
}

int64_t dharafs_backend_write_block(int64_t block_num, int64_t *buf) {
    if (block_num < 0 || block_num >= HOST_DISK_BLOCKS) {
        return -1;
    }
    memcpy(g_virtual_disk + (size_t)block_num * HOST_DISK_BLOCK_BYTES, buf,
           HOST_DISK_BLOCK_BYTES);
    return 0;
}

void host_virtual_disk_reset(void) {
    memset(g_virtual_disk, 0, sizeof(g_virtual_disk));
}

/* ---- Allocator: calloc, not malloc -- DharaFS relies on freshly
 * allocated scratch/data buffers starting zeroed (e.g. the
 * continuation-block path-bytes region), and calloc also puts ASAN's
 * redzones at the real allocation boundary. */

int64_t *dharafs_alloc_bytes(int64_t n) {
    return (int64_t *)calloc((size_t)n, 1);
}

/* ---- Logging: plain stdout. */

int64_t dharafs_log_puts(const char *s) {
    fputs(s, stdout);
    return 0;
}

int64_t dharafs_log_putc(int64_t c) {
    fputc((int)c, stdout);
    return 0;
}

int64_t dharafs_log_put_hex32(uint32_t v) {
    fprintf(stdout, "%08x", v);
    return 0;
}
