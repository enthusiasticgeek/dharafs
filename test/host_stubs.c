/* Host test harness: implements the small set of consumer-provided
 * externs src/lib.vani documents as its real environment-specific
 * seams (see src/lib.vani's own header comment / README.md) --
 * block I/O, the allocator, logging, and the media-encryption hook
 * (stubbed to always-off, since this package's own Tier-1 scope
 * excludes any real cipher). Everything mechanical (buffer/scratch/
 * dirindex/snapshot accessors) is provided by runtime/dharafs_runtime.c
 * and is NOT reimplemented here.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- Block I/O: an in-memory "disk" standing in for a real backend. */

#define HOST_DISK_BLOCKS 2200
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

/* ---- Media-encryption hook: always off. A consumer that wants real
 * tamper-detected encryption implements these three for real -- see
 * Dhruva OS's own round-69 ChaCha20-Poly1305 AEAD implementation for
 * a worked example of what a real backing implementation looks like. */

uint32_t dharafs_crypto_get_enabled(void) { return 0; }

int64_t dharafs_crypto_encrypt_block(int64_t block_num, int64_t *plaintext, int64_t *out_ciphertext) {
    (void)block_num;
    memcpy(out_ciphertext, plaintext, HOST_DISK_BLOCK_BYTES);
    return 0;
}

int64_t dharafs_crypto_decrypt_block(int64_t block_num, int64_t *ciphertext, int64_t *out_plaintext) {
    (void)block_num;
    memcpy(out_plaintext, ciphertext, HOST_DISK_BLOCK_BYTES);
    return 0;
}
