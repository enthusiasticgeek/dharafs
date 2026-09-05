/* Portable runtime for src/fsqueue.vani's own scratch buffers and
 * 8-slot state table. Pure, mechanical, zero scheduler/OS dependency
 * -- link this file whenever you use fsqueue.vani (src/lib_queued.vani
 * or src/lib_tier3.vani), in addition to runtime/dharafs_runtime.c.
 *
 * Table layout matches Dhruva OS's own boot/fsqueue_state.S exactly
 * (8 fixed slots; each queued write's data capped at 448 bytes,
 * dharafs_block_payload_cap()'s own limit; 32-byte paths, matching
 * core.vani's own path cap).
 *
 * Does NOT implement current_eff_prio/current_task_get -- fsqueue.vani
 * declares those itself as the one genuine, unavoidable
 * scheduler-specific extern this feature needs (see that file's own
 * header comment); a consumer without a real scheduler can stub both
 * to a fixed value and the queue still works correctly, just with
 * every request tying on priority and falling back to FIFO order.
 */
#include <stdint.h>

#define FSQUEUE_SLOTS 8

static int64_t g_fsqueue_valid[FSQUEUE_SLOTS];
static int64_t g_fsqueue_priority[FSQUEUE_SLOTS];
static int64_t g_fsqueue_task_id[FSQUEUE_SLOTS];
static int64_t g_fsqueue_op_type[FSQUEUE_SLOTS];
static int64_t g_fsqueue_path_len[FSQUEUE_SLOTS];
static int64_t g_fsqueue_data_len[FSQUEUE_SLOTS];
static int64_t g_fsqueue_owner_uid[FSQUEUE_SLOTS];
static int64_t g_fsqueue_owner_gid[FSQUEUE_SLOTS];
static int64_t g_fsqueue_mode[FSQUEUE_SLOTS];
static int64_t g_fsqueue_seq[FSQUEUE_SLOTS];
static int64_t g_fsqueue_result[FSQUEUE_SLOTS];
static uint32_t g_fsqueue_next_seq = 0;
static uint8_t g_fsqueue_path_bytes[FSQUEUE_SLOTS * 32];
static uint8_t g_fsqueue_data_bytes[FSQUEUE_SLOTS * 448];

#define ACCESSOR_PAIR(NAME)                                             \
    int64_t NAME##_get_at(uint32_t i) { return g_##NAME[i % FSQUEUE_SLOTS]; } \
    int64_t NAME##_set_at(uint32_t i, uint32_t v) { g_##NAME[i % FSQUEUE_SLOTS] = v; return 0; }

ACCESSOR_PAIR(fsqueue_valid)
ACCESSOR_PAIR(fsqueue_priority)
ACCESSOR_PAIR(fsqueue_task_id)
ACCESSOR_PAIR(fsqueue_op_type)
ACCESSOR_PAIR(fsqueue_path_len)
ACCESSOR_PAIR(fsqueue_data_len)
ACCESSOR_PAIR(fsqueue_owner_uid)
ACCESSOR_PAIR(fsqueue_owner_gid)
ACCESSOR_PAIR(fsqueue_mode)
ACCESSOR_PAIR(fsqueue_seq)
ACCESSOR_PAIR(fsqueue_result)

int64_t fsqueue_next_seq_get(void) { return g_fsqueue_next_seq; }
int64_t fsqueue_next_seq_set(uint32_t v) { g_fsqueue_next_seq = v; return 0; }

int64_t fsqueue_get_path_byte(uint32_t combined_index) { return g_fsqueue_path_bytes[combined_index % (FSQUEUE_SLOTS * 32)]; }
int64_t fsqueue_set_path_byte(uint32_t combined_index, uint32_t v) { g_fsqueue_path_bytes[combined_index % (FSQUEUE_SLOTS * 32)] = (uint8_t)v; return 0; }
int64_t fsqueue_get_data_byte(uint32_t combined_index) { return g_fsqueue_data_bytes[combined_index % (FSQUEUE_SLOTS * 448)]; }
int64_t fsqueue_set_data_byte(uint32_t combined_index, uint32_t v) { g_fsqueue_data_bytes[combined_index % (FSQUEUE_SLOTS * 448)] = (uint8_t)v; return 0; }

static int64_t g_fsqueue_path_scratch[(32 + 7) / 8];
static int64_t g_fsqueue_data_scratch[(448 + 7) / 8];
int64_t *fsqueue_path_scratch_get(void) { return g_fsqueue_path_scratch; }
int64_t *fsqueue_data_scratch_get(void) { return g_fsqueue_data_scratch; }
