/* Tier 1's own consumer-provided media-encryption hook stub: always
 * off, ciphertext == plaintext (never actually reached, since
 * dharafs_crypto_get_enabled always returns 0 -- core.vani's
 * dharafs_block_read/write never call encrypt_block/decrypt_block at
 * all in that case). Link this ONLY when testing src/lib.vani (Tier
 * 1) -- Tier 2 (src/lib_tier2.vani) provides a real implementation of
 * these same three names via runtime/dharafs_media_crypto_runtime.c,
 * and linking both together would be a duplicate-symbol error (see
 * test/host_stubs.c's own header comment for why they're split out
 * of that shared file).
 */
#include <stdint.h>
#include <string.h>

uint32_t dharafs_crypto_get_enabled(void) { return 0; }

int64_t dharafs_crypto_encrypt_block(int64_t block_num, int64_t *plaintext, int64_t *out_ciphertext) {
    (void)block_num;
    memcpy(out_ciphertext, plaintext, 512);
    return 0;
}

int64_t dharafs_crypto_decrypt_block(int64_t block_num, int64_t *ciphertext, int64_t *out_plaintext) {
    (void)block_num;
    memcpy(out_plaintext, ciphertext, 512);
    return 0;
}
