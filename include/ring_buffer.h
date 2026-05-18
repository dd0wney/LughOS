#ifndef RING_BUFFER_H
#define RING_BUFFER_H

#include "lugh.h"

/* Power-of-2 capacity for cheap modulo via bitwise AND */
#define IPC_RING_CAPACITY 256u

typedef struct {
    volatile uint32_t head;     /* next write slot — ipc_send path   */
    volatile uint32_t tail;     /* next read slot  — auditor_tick   */
    uint32_t          overflow; /* dropped messages since last drain  */
    message_t         buf[IPC_RING_CAPACITY];
} ipc_ring_t;

void     ring_init(ipc_ring_t *r);
int      ring_push(ipc_ring_t *r, const message_t *m); /* 0 = dropped (full) */
int      ring_pop (ipc_ring_t *r,       message_t *out); /* 0 = empty        */
uint32_t ring_len (const ipc_ring_t *r);

#endif /* RING_BUFFER_H */
