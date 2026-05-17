#include "lugh.h"
#include "nngcompat.h"
#include "security.h"
#include "crypto.h"
#include "watchdog.h"

/**
 * Maximum number of IPC channels
 * Fixed size per NASA Power of Ten rule 3
 */
#define MAX_IPC_CHANNELS 16 // NASA Power of Ten Rule 2, 3: Fixed-size, bounded array

/**
 * IPC channel structure
 */
typedef struct {
    int id;                   /* Channel ID */
    bool in_use;              /* Whether this channel is active */
    nng_socket_t socket;      /* NNG socket for this channel */
    uint32_t security_level;  /* Security level for access control */
    uint32_t domain;          /* Domain ID for isolation */
    uint8_t _padding[4];      /* Explicit padding per CERT DCL39-C */
} ipc_channel_t;

/* Fixed allocation per NASA Power of Ten rule 3 */
static ipc_channel_t channels[MAX_IPC_CHANNELS];

/* Initialize the IPC subsystem */
int init_ipc(void) {
    log_message(LOG_INFO, "Initializing IPC subsystem\n");
    nng_init();
    // NASA Power of Ten Rule 2: Bounded loop for channel initialization
    for (int i = 0; i < MAX_IPC_CHANNELS; i++) {
        channels[i].id = i;
        channels[i].in_use = false;
        channels[i].security_level = 0;
        channels[i].domain = 0;
    }
    log_message(LOG_INFO, "IPC subsystem initialized successfully\n");
    return 0;
}

/**
 * Create a new IPC channel
 * 
 * @param security_level Security level for access control
 * @param domain Domain ID for isolation
 * @param protocol Protocol type (NNG_PROTO_*)
 * @return Channel ID or negative error code
 */
int ipc_create_channel(uint32_t security_level, uint32_t domain, int protocol) {
    int channel_id = -1;
    // NASA Power of Ten Rule 2: Bounded loop to find free channel
    for (int i = 0; i < MAX_IPC_CHANNELS; i++) {
        if (!channels[i].in_use) {
            channel_id = i;
            break;
        }
    }
    if (channel_id < 0) {
        log_message(LOG_ERROR, "Failed to create IPC channel: no free slots\n");
        return -1;
    }
    // NASA Power of Ten Rule 6: Check return value of socket creation
    int rv = nng_socket_create(&channels[channel_id].socket, protocol);
    if (rv != NNG_OK) {
        log_message(LOG_ERROR, "Failed to create NNG socket: %d\n", rv);
        return -2;
    }
    channels[channel_id].in_use = true;
    channels[channel_id].security_level = security_level;
    channels[channel_id].domain = domain;
    log_message(LOG_INFO, "Created IPC channel %d (security: %u, domain: %u)\n",
                channel_id, security_level, domain);
    return channel_id;
}

/**
 * Close an IPC channel
 * 
 * @param channel_id Channel ID
 * @return 0 on success or negative error code
 */
int ipc_close_channel(int channel_id) {
    // SEI CERT ARR30-C: Validate channel ID
    if (channel_id < 0 || channel_id >= MAX_IPC_CHANNELS) {
        log_message(LOG_ERROR, "Invalid channel ID: %d\n", channel_id);
        return -1;
    }
    if (!channels[channel_id].in_use) {
        log_message(LOG_WARNING, "Channel %d already closed\n", channel_id);
        return -2;
    }
    // NASA Power of Ten Rule 6: Check return value of socket close
    int rv = nng_socket_close(&channels[channel_id].socket);
    if (rv != NNG_OK) {
        log_message(LOG_ERROR, "Failed to close NNG socket: %d\n", rv);
        return -3;
    }
    channels[channel_id].in_use = false;
    log_message(LOG_INFO, "Closed IPC channel %d\n", channel_id);
    return 0;
}

/**
 * Send a message on an IPC channel
 * 
 * @param channel_id Channel ID
 * @param msg Message to send
 * @return 0 on success or negative error code
 */
int ipc_send(int channel_id, message_t* msg) {
    /* Validate parameters per SEI CERT ARR30-C */
    if (msg == NULL) {
        log_message(LOG_ERROR, "NULL message pointer in ipc_send\n");
        return -1;
    }
    
    /* Validate channel ID */
    if (channel_id < 0 || channel_id >= MAX_IPC_CHANNELS || !channels[channel_id].in_use) {
        log_message(LOG_ERROR, "Invalid channel ID: %d\n", channel_id);
        return -2;
    }
    
    /* Ensure string termination per CERT STR31-C */
    msg->payload[MAX_MSG_SIZE - 1] = '\0';
    
    /* Calculate checksum per NASA Power of Ten rule 6 */
    msg->checksum = calculate_checksum(msg->payload, strlen(msg->payload));
    
    /* Convert to NNG message */
    nng_msg_t *nng_msg;
    int rv = lugh_message_to_nng(msg, &nng_msg);
    if (rv != NNG_OK) {
        log_message(LOG_ERROR, "Failed to convert message: %d\n", rv);
        return -3;
    }
    
    /* Observe message on telemetry ring before delivery */
    if (watchdog_enabled)
        ring_push(&ipc_ring, msg);

    /* Send message */
    rv = nng_send(&channels[channel_id].socket, nng_msg, 0);
    if (rv != NNG_OK) {
        log_message(LOG_ERROR, "Failed to send message: %d\n", rv);
        return -4;
    }
    
    log_message(LOG_DEBUG, "Sent message on channel %d\n", channel_id);
    return 0;
}

/**
 * Receive a message from an IPC channel
 * 
 * @param channel_id Channel ID
 * @param msg Buffer to store received message
 * @param nonblock Whether to block until a message is available
 * @return 0 on success or negative error code
 */
int ipc_recv(int channel_id, message_t* msg, bool nonblock) {
    /* Validate parameters per SEI CERT ARR30-C */
    if (msg == NULL) {
        log_message(LOG_ERROR, "NULL message pointer in ipc_recv\n");
        return -1;
    }
    
    /* Validate channel ID */
    if (channel_id < 0 || channel_id >= MAX_IPC_CHANNELS || !channels[channel_id].in_use) {
        log_message(LOG_ERROR, "Invalid channel ID: %d\n", channel_id);
        return -2;
    }
    
    /* Receive NNG message */
    nng_msg_t *nng_msg;
    int rv = nng_recv(&channels[channel_id].socket, &nng_msg, nonblock ? 1 : 0);
    if (rv != NNG_OK) {
        if (rv == NNG_ETIMEDOUT && nonblock) {
            /* Non-blocking receive with no message available */
            return -3;
        }
        log_message(LOG_ERROR, "Failed to receive message: %d\n", rv);
        return -4;
    }
    
    /* Convert from NNG message */
    rv = nng_message_to_lugh(nng_msg, msg);
    if (rv != NNG_OK) {
        log_message(LOG_ERROR, "Failed to convert message: %d\n", rv);
        nng_msg_free(nng_msg);
        return -5;
    }
    
    /* Free NNG message */
    nng_msg_free(nng_msg);
    
    /* Validate checksum per NASA Power of Ten rule 6 */
    uint32_t verify_sum = calculate_checksum(msg->payload, strlen(msg->payload));
    if (verify_sum != msg->checksum) {
        log_message(LOG_ERROR, "Message checksum failed in ipc_recv\n");
        return -6;
    }
    
    log_message(LOG_DEBUG, "Received message on channel %d\n", channel_id);
    return 0;
}