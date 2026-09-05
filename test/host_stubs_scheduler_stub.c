/* fsqueue.vani's own one genuine scheduler dependency:
 * current_eff_prio/current_task_get, called only from
 * dharafs_queue_submit (the Str convenience wrapper) -- every other
 * fsqueue function takes priority/task_id as explicit parameters and
 * has no scheduler dependency at all (see src/fsqueue.vani's own
 * header comment). Link this file whenever you use fsqueue.vani
 * (src/lib_queued.vani or src/lib_tier3.vani) and don't have your own
 * real scheduler to query -- a fixed value is a fine, honest
 * degradation: dharafs_queue_submit's own priority-ordering still
 * works correctly, it just ties on priority for every request and
 * falls back to pure FIFO (submission order).
 */
#include <stdint.h>

uint32_t current_eff_prio(void) { return 5; }
uint32_t current_task_get(void) { return 1; }
