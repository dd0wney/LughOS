#ifndef DOMAIN_GRAPH_H
#define DOMAIN_GRAPH_H

#include <stdint.h>

/* Domain transition matrix — explicit allow-list of (src_domain, dst_domain)
 * edges that ipc_create_channel / ipc_connect may traverse. Replaces the
 * flat CAP_CROSS_DOMAIN bypass with a per-edge policy: CAP_CROSS_DOMAIN
 * remains as an emergency-override capability for kernel-trusted tasks,
 * but ordinary cross-domain IPC must have an explicit edge.
 *
 * MAX_DOMAINS = 8 (one bit per dst-domain in each row's uint32_t bitmap).
 * Edges are directed: domain_edge_set(a, b) does NOT imply (b, a).
 *
 * Lifecycle:
 *   1. boot: domain_edges_init() — identity matrix (i -> i only).
 *   2. policy load: domain_edge_set(...) calls during system init.
 *   3. domain_edges_seal() before entering the main loop — refuses
 *      further mutations so a compromised task cannot rewrite the matrix.
 */

#define MAX_DOMAINS 8u

void domain_edges_init(void);

/* Returns 1 if src may reach dst, 0 otherwise. Out-of-range domains
 * (>= MAX_DOMAINS) always return 0. */
int  domain_edge_allowed(uint32_t src, uint32_t dst);

/* Returns 0 on success, -1 on out-of-range domain, -2 if sealed.
 * On success, also emits an AUDITOR_REC_DOMAIN_EDGE record so policy
 * mutations are auditable in the JEPA stream. */
int  domain_edge_set(uint32_t src, uint32_t dst);

/* Seals the matrix — subsequent domain_edge_set returns -2. Idempotent. */
void domain_edges_seal(void);

#endif /* DOMAIN_GRAPH_H */
