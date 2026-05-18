#include "lugh.h"
#include "memory.h"

/* Page frame allocator (Phase 3 B1).
 *
 * Reserves a fixed physical window above the kernel image and divides it
 * into 4 KB frames. A static bitmap tracks free/used state — 1 bit per
 * frame, set = in use, clear = free. NASA Power of Ten rule 5: all
 * frames are discovered at init; the bitmap is statically sized so the
 * worst-case footprint is known at compile time.
 *
 * Why this layout:
 *
 *   0x00000000  vector page (after boot copy on ARM)
 *   0x00010000  kernel .text starts (linker_arm.ld)
 *   0x000???    kernel .text/.data/.bss ends (~ 0x80000 today)
 *   0x000C0000  UND/ABT/IRQ stacks (64 KB each, see boot_arm.S)
 *   0x00100000  SVC stack top (boot CPU's kernel stack)
 *   0x00200000  ← FRAME_POOL_BASE: 2 MB safety gap above all the above
 *               4 MB pool follows (1024 frames @ 4 KB)
 *   0x00600000  end of allocatable physical pool
 *
 * versatilepb has 128 MB of DRAM total — we're using a tiny slice, easy
 * to grow once B4 lands and we know how many page tables + user pages
 * a real workload needs. B2/B3 will identity-map the kernel image and
 * device windows; the pool starts above any of that so we don't have
 * to special-case "frame happens to alias kernel data."
 *
 * Device windows that B2/B3 must identity-map (kept here for reference;
 * the actual paging code will consume these):
 *   ARM versatilepb:
 *     0x00000000  vectors (1 frame)
 *     0x10140000  PL190 VIC (1 frame)
 *     0x101E2000  SP804 timer (1 frame)
 *     0x101F1000  PL011 UART0 (1 frame)
 *     0x101F2000  PL011 UART1 (auditor telemetry) (1 frame)
 *   x86 i686:
 *     0x000B8000  VGA text buffer (1 frame)
 *     0x000F0000  BIOS ROM (read-only, 64 KB)
 *   The legacy 8259 PIC and 8253 PIT live at I/O ports (cli/outb), not
 *   in the MMIO map.
 */

#define FRAME_POOL_BASE   0x00200000u
#define FRAME_POOL_FRAMES 1024u
#define FRAME_BITMAP_WORDS ((FRAME_POOL_FRAMES + 31u) / 32u)

static uint32_t frame_bitmap[FRAME_BITMAP_WORDS];
static uint32_t frames_free;

void frame_allocator_init(void) {
    uint32_t i;
    for (i = 0u; i < FRAME_BITMAP_WORDS; i++) {
        frame_bitmap[i] = 0u;
    }
    frames_free = FRAME_POOL_FRAMES;
    log_message(LOG_INFO,
        "Frame allocator: %u frames x %u bytes starting at 0x%X "
        "(%u KB pool, %u bytes bitmap)\n",
        (unsigned int)FRAME_POOL_FRAMES,
        (unsigned int)MM_FRAME_SIZE,
        (unsigned int)FRAME_POOL_BASE,
        (unsigned int)((FRAME_POOL_FRAMES * MM_FRAME_SIZE) / 1024u),
        (unsigned int)(FRAME_BITMAP_WORDS * sizeof(uint32_t)));
}

uint32_t alloc_frame(void) {
    uint32_t i;
    /* Bounded linear scan per NASA Power of Ten rule 2. Frame count
     * is small (1024), and we don't need allocation performance to be
     * a kernel hot path — B2/B3 allocate page tables once at boot. */
    for (i = 0u; i < FRAME_POOL_FRAMES; i++) {
        uint32_t word = i / 32u;
        uint32_t bit  = i % 32u;
        if ((frame_bitmap[word] & (1u << bit)) == 0u) {
            frame_bitmap[word] |= (1u << bit);
            frames_free--;
            return FRAME_POOL_BASE + i * MM_FRAME_SIZE;
        }
    }
    log_message(LOG_ERROR, "alloc_frame: out of frames (%u total)\n",
        (unsigned int)FRAME_POOL_FRAMES);
    return 0u;
}

void free_frame(uint32_t phys_addr) {
    /* Validate the address: must be in pool, frame-aligned, and currently
     * marked as in-use. Double-frees and out-of-pool calls are logged but
     * tolerated — defensive per SEI CERT MEM30-C ("do not access freed
     * memory"; in our case "do not corrupt the bitmap on bad input"). */
    if (phys_addr < FRAME_POOL_BASE) {
        log_message(LOG_WARNING,
            "free_frame: address 0x%X below pool base 0x%X\n",
            phys_addr, (unsigned int)FRAME_POOL_BASE);
        return;
    }
    if ((phys_addr & (MM_FRAME_SIZE - 1u)) != 0u) {
        log_message(LOG_WARNING,
            "free_frame: address 0x%X not frame-aligned\n", phys_addr);
        return;
    }
    uint32_t idx = (phys_addr - FRAME_POOL_BASE) / MM_FRAME_SIZE;
    if (idx >= FRAME_POOL_FRAMES) {
        log_message(LOG_WARNING,
            "free_frame: index %u out of range\n", (unsigned int)idx);
        return;
    }
    uint32_t word = idx / 32u;
    uint32_t bit  = idx % 32u;
    if ((frame_bitmap[word] & (1u << bit)) == 0u) {
        log_message(LOG_WARNING,
            "free_frame: double-free at 0x%X (idx=%u)\n",
            phys_addr, (unsigned int)idx);
        return;
    }
    frame_bitmap[word] &= ~(1u << bit);
    frames_free++;
}

uint32_t frame_count_free(void) {
    return frames_free;
}
