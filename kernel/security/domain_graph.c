/* Domain transition matrix — see include/domain_graph.h for design notes.
 *
 * Storage: MAX_DOMAINS rows of uint32_t, where bit b of row a set iff
 *          domain a may reach domain b. One word per row keeps lookup to
 *          a single load + shift + AND, and bounded loops everywhere.
 *
 * Telemetry: every successful domain_edge_set emits an AUDITOR_REC_DOMAIN_EDGE
 *          record so the JEPA encoder sees policy mutations as first-class
 *          events alongside MSG / DENY / CHAN_CREATE / CHAN_CONNECT.
 */

#include "lugh.h"
#include "domain_graph.h"
#include "auditor.h"

static uint32_t      domain_edges[MAX_DOMAINS];
static volatile int  edges_sealed = 0;

void domain_edges_init(void) {
    /* Identity matrix — every domain reaches itself only.
     * Cross-domain edges must be added explicitly via domain_edge_set
     * before the seal. */
    uint32_t i;
    for (i = 0u; i < MAX_DOMAINS; i++) {
        domain_edges[i] = (1u << i);
    }
    edges_sealed = 0;
    log_message(LOG_INFO,
        "domain_graph: matrix initialised (identity, %u domains)\n",
        (unsigned int)MAX_DOMAINS);
}

int domain_edge_allowed(uint32_t src, uint32_t dst) {
    if (src >= MAX_DOMAINS || dst >= MAX_DOMAINS) {
        /* Out-of-range domains never reach anything via the matrix —
         * a malicious task that sets domain = 999 cannot bypass the
         * check by overflowing past the matrix. CAP_CROSS_DOMAIN may
         * still grant access, but that's an explicit task-level bypass. */
        return 0;
    }
    return (domain_edges[src] & (1u << dst)) != 0u ? 1 : 0;
}

int domain_edge_set(uint32_t src, uint32_t dst) {
    if (src >= MAX_DOMAINS || dst >= MAX_DOMAINS) {
        log_message(LOG_ERROR,
            "domain_edge_set: out-of-range domain (%u -> %u, max=%u)\n",
            (unsigned int)src, (unsigned int)dst,
            (unsigned int)MAX_DOMAINS);
        return -1;
    }
    if (edges_sealed) {
        log_message(LOG_ERROR,
            "domain_edge_set: refused (matrix sealed, %u -> %u)\n",
            (unsigned int)src, (unsigned int)dst);
        return -2;
    }
    domain_edges[src] |= (1u << dst);
    log_message(LOG_INFO,
        "domain_edge_set: edge %u -> %u allowed\n",
        (unsigned int)src, (unsigned int)dst);
    auditor_domain_edge(src, dst, /*added=*/1u);
    return 0;
}

void domain_edges_seal(void) {
    if (!edges_sealed) {
        edges_sealed = 1;
        log_message(LOG_INFO, "domain_graph: matrix sealed\n");
    }
}
