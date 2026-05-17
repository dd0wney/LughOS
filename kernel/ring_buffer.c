#include "ring_buffer.h"

/* Plain byte copy — must NOT use the kernel's security-gated memcpy here.
 * The ring buffer is an internal kernel primitive; validation happens at
 * the IPC boundary before ipc_send() is called, not inside the buffer. */
static void ring_copy(void *dst, const void *src, uint32_t n) {
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    uint32_t i;
    for (i = 0; i < n; i++)
        d[i] = s[i];
}

void ring_init(ipc_ring_t *r) {
    r->head = 0;
    r->tail = 0;
    r->overflow = 0;
}

int ring_push(ipc_ring_t *r, const message_t *m) {
    uint32_t next = (r->head + 1u) & (IPC_RING_CAPACITY - 1u);
    if (next == r->tail) {
        r->overflow++;
        return 0;  /* full — drop newest, never block the IPC path */
    }
    ring_copy(&r->buf[r->head], m, sizeof(message_t));
    r->head = next;
    return 1;
}

int ring_pop(ipc_ring_t *r, message_t *out) {
    if (r->head == r->tail)
        return 0;  /* empty */
    ring_copy(out, &r->buf[r->tail], sizeof(message_t));
    r->tail = (r->tail + 1u) & (IPC_RING_CAPACITY - 1u);
    return 1;
}

uint32_t ring_len(const ipc_ring_t *r) {
    return (r->head - r->tail) & (IPC_RING_CAPACITY - 1u);
}
