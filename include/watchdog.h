#ifndef WATCHDOG_H
#define WATCHDOG_H

#include "lugh.h"
#include "ring_buffer.h"

#define WATCHDOG_MAGIC             0x4C474849UL  /* "LGHI" = LughOS IPC */
#define WATCHDOG_TELEMETRY_VERSION 1u

#define WATCHDOG_REC_MSG       0u  /* normal IPC message event  */
#define WATCHDOG_REC_OVERFLOW  1u  /* ring dropped N messages   */
#define WATCHDOG_REC_HEARTBEAT 2u  /* 1-second keepalive        */

/* Fixed-size telemetry record emitted on COM2.
 * 44 bytes packed. Python struct format: '<IHHQBxxxII16s' */
typedef struct __attribute__((packed)) {
    uint32_t magic;           /* WATCHDOG_MAGIC                       */
    uint16_t version;         /* WATCHDOG_TELEMETRY_VERSION           */
    uint16_t record_type;     /* WATCHDOG_REC_*                       */
    uint64_t jiffies;         /* hw_get_jiffies() at emit time        */
    uint8_t  priority;        /* msg.priority (0=HIGH,1=MED,2=LOW)    */
    uint8_t  _pad[3];
    uint32_t operation;       /* msg.operation (OP_*)                 */
    uint32_t checksum;        /* msg.checksum passed through          */
    uint8_t  payload_hash[16]; /* 4× FNV-1a-32 of payload            */
} watchdog_record_t;

/* Exported globals — defined in services/watchdog/exporter.c */
extern ipc_ring_t        ipc_ring;
extern volatile uint8_t  watchdog_enabled;

void watchdog_init(void);
void watchdog_tick(void);

#endif /* WATCHDOG_H */
