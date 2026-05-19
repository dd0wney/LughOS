/* Phase 4 F2: prefetch / data abort diagnostics.
 *
 * The panic stubs in exceptions.S used to write a single letter ('P' or
 * 'D') and busy-loop. That made the EXC:P regression after B4 (DACR=
 * Client) basically un-debuggable — we knew the prefetch abort fired
 * somewhere in user-mode but had no way to identify the offending VA.
 *
 * The stubs now hand control here BEFORE printing the panic banner and
 * looping, with the architecturally-defined fault values already
 * loaded in registers:
 *
 *   arm_pabort_diagnose(fault_pc, spsr)
 *       fault_pc = LR_abt - 4          (faulting instruction VA)
 *       spsr     = SPSR_abt            (CPSR snapshot at fault time)
 *
 *   arm_dabort_diagnose(fault_pc, dfar, dfsr, spsr)
 *       fault_pc = LR_abt - 8          (ARMv5: data abort LR offset)
 *       dfar     = CP15 c6,c0,0        (Data Fault Address)
 *       dfsr     = CP15 c5,c0,0        (Data Fault Status — see below)
 *       spsr     = SPSR_abt
 *
 * DFSR (ARMv5) encoding — bits[3:0] = fault status; useful values are:
 *   0b0001 alignment        0b0010 debug
 *   0b0101 translation L1   0b0111 translation L2
 *   0b1001 domain L1        0b1011 domain L2
 *   0b1101 permission L1    0b1111 permission L2
 * Bit 11 (W) distinguishes write (1) from read (0). Bits[7:4] are the
 * domain number that triggered the fault.
 *
 * We intentionally call log_message here even though the MMU is on:
 * log_message → serial_write → PL011 MMIO at 0x101F1000. That region
 * is identity-mapped by arm_mmu.c with AP=01 (kernel RW), so we're not
 * relying on any user-mode mapping. If log_message itself faulted we'd
 * recurse into the abort handler — kept it linear and simple.
 *
 * After we dump, control returns to the assembly stub which prints
 * "EXC:P\n" / "EXC:D\n" and busy-loops, preserving the existing
 * "panic stops the kernel" semantics. Telemetry emission (AUDITOR_REC_FAULT)
 * added in Phase 4 F3. Replacing the busy-loop with a graceful task-terminate
 * path is deferred to a later phase. */

#include "lugh.h"
#include "auditor.h"

void arm_pabort_diagnose(uint32_t fault_pc, uint32_t spsr)
{
    /* Identify the pre-fault CPU mode (low 5 bits of SPSR). The
     * interesting ones for us: 0x10 = USR, 0x13 = SVC, 0x1F = SYS. If
     * the fault came from kernel mode we have a much bigger problem
     * than a wayward user task. */
    uint32_t mode = spsr & 0x1Fu;
    uint32_t current_task_id =
        (current_task != NULL) ? current_task->task_id : 0u;

    log_message(LOG_FATAL,
        "PABORT: pc=0x%X spsr=0x%X mode=0x%X task=%u\n",
        fault_pc, spsr, mode, current_task_id);
    auditor_fault(fault_pc, 0u, 0u, spsr, AUDITOR_FAULT_PABORT);
}

void arm_dabort_diagnose(uint32_t fault_pc, uint32_t dfar,
                         uint32_t dfsr, uint32_t spsr)
{
    uint32_t mode      = spsr & 0x1Fu;
    uint32_t status    = dfsr & 0xFu;        /* bits[3:0]    */
    uint32_t domain    = (dfsr >> 4) & 0xFu; /* bits[7:4]    */
    uint32_t is_write  = (dfsr >> 11) & 1u;  /* bit 11 (W)   */
    uint32_t current_task_id =
        (current_task != NULL) ? current_task->task_id : 0u;

    log_message(LOG_FATAL,
        "DABORT: pc=0x%X va=0x%X dfsr=0x%X status=0x%X dom=%u %s "
        "spsr=0x%X mode=0x%X task=%u\n",
        fault_pc, dfar, dfsr, status, domain,
        is_write ? "write" : "read", spsr, mode, current_task_id);
    {
        uint8_t ft = is_write ? AUDITOR_FAULT_DABORT_WRITE : AUDITOR_FAULT_DABORT_READ;
        auditor_fault(fault_pc, dfar, dfsr, spsr, ft);
    }
}
