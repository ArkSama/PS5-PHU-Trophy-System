#pragma once
// phu_fw_offsets — firmware-specific kernel / struct offsets for PHU Overlay.
//
// Goal : isolate every fw-dependent magic number into a single table so the
// same payload binary can run on fw 3.00 → 10.01+ by looking up offsets at
// runtime instead of hardcoding 9.40 inline everywhere.
//
// Covered exploit path : **kstuff** (sleirsgoevy / EchoStretch fork).
// byepervisor ≤ 2.xx and ps5-hen 1.00→4.51 are NOT supported — ps5-hen is
// unstable / unfinished per 2026-04-21 Arksama feedback, kstuff covers the
// same range more reliably.
//
// Runtime flow :
//   1. phu_fw_get_current_sdk_version() reads kern.sdk_version via sysctl
//      → returns u32 packed like 0x09400000 for fw 9.40.
//   2. phu_fw_offsets_current() walks the table and returns the entry whose
//      [sdk_version_min, sdk_version_max] range contains the current value.
//   3. Callers (probe, hook_vout, proc_rw, phu_stats) use fields from this
//      struct instead of their own hardcoded constants.
//
// Coverage strategy :
//   - One entry per MAJOR version (3.x, 4.x, 5.x, …, 10.x) covers most cases
//     because Sony typically only rebuilds offset-sensitive structs on SDK
//     major bumps.
//   - Minor-specific override entries when Sony shifts structs mid-cycle
//     (known historical events : some 8.x minors changed allproc alignment).
//   - Table is searched LINEARLY : list more-specific (narrower sdk range)
//     entries FIRST so they shadow the generic major entry below them.

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// One entry = one fw range. Narrow the range to a single sdk_version value
// for minor-specific overrides ; use a wide range (e.g. 0x09000000..0x09FFFFFF)
// for "all 9.x minors use these offsets" entries.
typedef struct {
    // Human-readable label shown in klog dumps : "9.40", "8.x generic", etc.
    const char *fw_label;

    // SDK version range (inclusive) from kern.sdk_version. Format :
    //   0xAABBCCDD  where AA = major hex, BB = minor hex
    // Example : 9.40 = 0x09400000. Range 0x09000000..0x09FFFFFF = all 9.x.
    uint32_t sdk_version_min;
    uint32_t sdk_version_max;

    // === Kernel globals — offsets from kernel_base ============================
    uint64_t kbase_allproc;        // head of allproc linked list
    uint64_t kbase_sysentvec;      // sysentvec global (+14 = kstuff alive magic)
    // PS4-compat sysentvec global (+14 = PS4 compat kstuff alive magic).
    // etaHEN pause_resume_kstuff flips BOTH this and kbase_sysentvec together
    // (daemon/source/msg.cpp:248-255). Delta is constant +0x178 on 3.x-10.x.
    // 0 = unsupported on this fw => phu_kstuff_flip must refuse to flip.
    uint64_t kbase_sysentvec_ps4;

    // === FreeBSD proc struct offsets ==========================================
    uint32_t proc_p_pid;            // int pid field
    uint32_t proc_p_vmspace;        // vmspace pointer
    uint32_t proc_titleid;          // PS5-specific title_id char[10] cache
    uint32_t proc_p_next;           // next pointer in allproc linked list

    // === vmspace + vm_map =====================================================
    uint32_t vm_map_root;           // vm_map.root (RB-tree root, diagnostic)
    uint32_t vm_map_pmap;           // vm_map.pmap pointer
    uint32_t vm_map_sentinel_next;  // offset of "next" in the sentinel node

    // === PMAP =================================================================
    uint32_t pmap_pm_pml4;          // PML4 virtual address pointer
    uint32_t pmap_pm_cr3;           // CR3 physical address (PML4 PA)

    // === vm_map_entry (filter RW ranges) ======================================
    uint32_t vme_start;             // range start VA
    uint32_t vme_end;                // range end VA
    uint32_t vme_protection;        // prot flags (bits 0-2 = RWX)
    uint32_t vme_max_protection;    // max prot flags
    uint32_t vme_next;              // next pointer in LL

    // === DMAP base fallback ===================================================
    // Real DMAP base is derived at runtime (pm_pml4 − pm_cr3). This fallback
    // is used only if runtime derivation fails.
    //   0                   = unknown for this fw — caller aborts cleanly
    //                         instead of corrupting kernel memory.
    //   0xffff873b00000000  = 9.x empirical (validated on 9.40 dev baseline).
    // Sony rebases DMAP at most once per major fw, so 9.x minors share.
    uint64_t dmap_base_fallback;
} phu_fw_offsets_t;

// Read kern.sdk_version and return packed u32 (e.g. 0x09400000 for 9.40).
// Returns 0 on sysctl failure.
uint32_t phu_fw_get_current_sdk_version(void);

// Look up offsets for a specific SDK version. Returns NULL if no entry
// matches (unsupported fw). Caller should warn + refuse to install hook.
const phu_fw_offsets_t *phu_fw_offsets_lookup(uint32_t sdk_version);

// Convenience : reads kern.sdk_version once, caches, returns offsets.
// Returns NULL if fw is unsupported ; log-and-refuse recommended.
const phu_fw_offsets_t *phu_fw_offsets_current(void);

// Human-readable log of the resolved entry (to klog). No-op if current fw
// is unsupported. Useful as a boot-time sanity check.
void phu_fw_offsets_log_current(void);

#ifdef __cplusplus
}
#endif
