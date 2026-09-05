/* Portable runtime for src/crypto.vani's own scratch buffers (SHA-256,
 * HMAC-SHA256, PBKDF2-HMAC-SHA256). Pure, mechanical, zero FS/OS
 * dependency -- link this file whenever you use crypto.vani, whether
 * that's via src/lib_tier2.vani, src/lib_verified.vani, or standalone
 * (crypto.vani has no idea DharaFS-the-filesystem exists).
 *
 * Deliberately a SEPARATE file from runtime/dharafs_runtime.c (Tier
 * 1's own core-FS accessors): a Tier-1-only consumer never links this
 * file at all, keeping the crypto scratch surface entirely out of a
 * build that doesn't want it.
 */
#include <stdint.h>

#define SCRATCH_BUF(NAME, SIZE)                                \
    static int64_t NAME##_storage[((SIZE) + 7) / 8];           \
    int64_t *NAME##_get(void) { return NAME##_storage; }

#define SCRATCH_BUF_PTR(NAME, SIZE)                            \
    static int64_t NAME##_storage[((SIZE) + 7) / 8];           \
    int64_t *NAME##_ptr(void) { return NAME##_storage; }

/* SHA-256: h (running hash state), k (round constants, re-derived on
 * every sha256_hash call -- see crypto.vani's own comment on why),
 * w (message schedule), padded (message + FIPS 180-4 padding, sized
 * for up to a 4096-byte message: 4096 + 1 + 63 pad + 8 length = 4168). */
SCRATCH_BUF(sha256_h_scratch, 32)
SCRATCH_BUF(sha256_k_scratch, 256)
SCRATCH_BUF(sha256_w_scratch, 256)
SCRATCH_BUF(sha256_padded_scratch, 4168)

/* HMAC-SHA256: key_block (64-byte K'), msg_scratch (64-byte pad block
 * + up to 64 bytes of message -- hmac_sha256's own documented cap),
 * inner_hash (32-byte intermediate digest). */
SCRATCH_BUF_PTR(hmac_key_block, 64)
SCRATCH_BUF_PTR(hmac_msg_scratch, 128)
SCRATCH_BUF_PTR(hmac_inner_hash, 32)

/* PBKDF2-HMAC-SHA256: salt_ctr (up to 32-byte salt + 4-byte block-index
 * counter), u and t (32-byte U_i / running T accumulator). */
SCRATCH_BUF_PTR(pbkdf2_salt_ctr, 36)
SCRATCH_BUF_PTR(pbkdf2_u, 32)
SCRATCH_BUF_PTR(pbkdf2_t, 32)
