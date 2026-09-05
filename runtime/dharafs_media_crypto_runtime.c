/* Portable runtime for src/media_crypto.vani: the on/off + key-
 * initialized toggle state, and the fixed-size AEAD scratch buffers.
 * Pure, mechanical, zero FS/OS dependency -- link this file whenever
 * you use media_crypto.vani (src/lib_tier2.vani or
 * src/lib_encrypted.vani), in addition to runtime/dharafs_runtime.c
 * and runtime/dharafs_crypto_runtime.c.
 *
 * A Tier-1-only consumer (src/lib.vani) never links this file: Tier 1
 * declares dharafs_crypto_get_enabled/_encrypt_block/_decrypt_block as
 * a consumer-provided extern hook instead (see test/host_stubs.c for
 * an example always-off stub), so this file's own
 * dharafs_crypto_get_enabled would collide with that consumer-provided
 * one if both were ever linked into the same binary -- they are
 * mutually exclusive by design, matching src/lib.vani and
 * src/lib_tier2.vani never being used together (see README.md).
 */
#include <stdint.h>

#define SCRATCH_BUF_PTR(NAME, SIZE)                            \
    static int64_t NAME##_storage[((SIZE) + 7) / 8];           \
    int64_t *NAME##_ptr(void) { return NAME##_storage; }

/* Off by default, key not initialized by default -- linking this file
 * changes nothing for a consumer who never calls
 * dharafs_crypto_set_enabled(1) / dharafs_crypto_key_init(...). */
static uint32_t g_dharafs_crypto_enabled = 0;
static uint32_t g_dharafs_crypto_key_initialized = 0;

uint32_t dharafs_crypto_get_enabled(void) { return g_dharafs_crypto_enabled; }
uint32_t dharafs_crypto_set_enabled(uint32_t v) { g_dharafs_crypto_enabled = v; return 0; }
uint32_t dharafs_crypto_key_initialized_get(void) { return g_dharafs_crypto_key_initialized; }
uint32_t dharafs_crypto_key_initialized_set(uint32_t v) { g_dharafs_crypto_key_initialized = v; return 0; }

SCRATCH_BUF_PTR(dharafs_crypto_key, 32)
SCRATCH_BUF_PTR(dharafs_crypto_nonce, 12)
SCRATCH_BUF_PTR(dharafs_crypto_state, 64)
SCRATCH_BUF_PTR(dharafs_crypto_working, 64)
SCRATCH_BUF_PTR(dharafs_crypto_keystream, 512)
SCRATCH_BUF_PTR(dharafs_crypto_block_scratch, 16)
SCRATCH_BUF_PTR(dharafs_crypto_otk_scratch, 32)
SCRATCH_BUF_PTR(dharafs_crypto_mac_data_scratch, 576)
SCRATCH_BUF_PTR(dharafs_crypto_tag_scratch, 16)
SCRATCH_BUF_PTR(dharafs_crypto_computed_tag_scratch, 16)
SCRATCH_BUF_PTR(dharafs_crypto_aad_scratch, 8)
SCRATCH_BUF_PTR(dharafs_crypto_meta_sector_scratch, 512)
