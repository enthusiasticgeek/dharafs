/* Portable runtime for src/verified_io.vani's own scratch buffers.
 * Pure, mechanical, zero FS/OS dependency -- link this file whenever
 * you use verified_io.vani (src/lib_tier2.vani or
 * src/lib_verified.vani), in addition to runtime/dharafs_runtime.c
 * and runtime/dharafs_crypto_runtime.c.
 */
#include <stdint.h>

#define SCRATCH_BUF(NAME, SIZE)                                \
    static int64_t NAME##_storage[((SIZE) + 7) / 8];           \
    int64_t *NAME##_get(void) { return NAME##_storage; }

/* Sized to match core.vani's own 32-byte path cap: a companion path
 * (path + ".sha256", guarded to never exceed 32 bytes -- see
 * core.vani's dharafs_verified_companion_path_raw) and two 32-byte
 * SHA-256 digests. */
SCRATCH_BUF(dharafs_verified_companion_scratch, 32)
SCRATCH_BUF(dharafs_verified_digest_a_scratch, 32)
SCRATCH_BUF(dharafs_verified_digest_b_scratch, 32)
