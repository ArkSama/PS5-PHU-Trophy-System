/*
 * phu_trophy.cpp — v1.15.0 Phase B1 — SceShellCore "AAAA00000" patch.
 *
 * Two-stage trophy bypass (see phu_trophy.h for the full architecture):
 * B1 = THIS FILE: daemon-side AAAA00000 string patch via DMAP
 * B2 = TBD: client-side cache inject (libSceNpManager DAT_01063128) via ptrace
 * B3 = TBD: SceShellCore restart detection + re-patch
 *
 * v1.15.0-β2 (this revision) — implements B1 + B2:
 * B1 (init_boot):
 * 1. fw 9.40 guard
 * 2. Resolve SceShellCore via title_id (NPXS40082) + Hijacker
 * 3. Probe image base (0x01000000 or 0x00000000)
 * 4. kstuff wrap + DMAP-patch 4 "AAAA00000" → "ZZZZZZZZZ" strings
 * 5. Pre/post verify reads to confirm patch took effect
 * B2 (apply_per_game):
 * 1. Resolve game-side libSceNpManager.sprx via Hijacker::getLib
 * 2. Poll DAT_01063128 for 5s (wait for NpAsmClient ctor)
 * 3. DMAP-inject fake NpTitleId (12 chars + 4 nulls) + non-zero secret
 * 4. Set flags +0xa4=1 (LAB_0102a38f branch), +0xa5=1 (old SDK),
 * +0xa6=1 (new SDK) to bypass `sceNpAsmClientGetNpTitleId` validation
 * B3 (check_persistence):
 * - Re-verify SceShellCore patch at every game-detect, re-apply on revert
 *
 * Source RE addresses (SceShellCore.elf fw 9.40, image base 0x01000000):
 * 0x02e7f488 — Trophy 2 main string
 * 0x02e7f494 — Trophy 2 NetSync string
 * 0x02e7fbe8 — Trophy 1 NetSync string
 * 0x02e7fbf4 — Trophy 1 main string
 *
 * Runtime VA = SceShellCore_runtime_base + (string_addr - 0x01000000).
 */
#include "phu_trophy.h"
#include "phu_config.h"
#include "phu_notify.h"
#include "phu_kstuff_ctrl.h"
#include "phu_fw_offsets.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h> /* free — libNineS get_proc_by_title_id mallocs */
#include <unistd.h> /* usleep — B2 polls DAT_01063128 allocation */
#include <stdint.h>
#include <fcntl.h> /* open — B6 reads npbind.dat */
#include <sys/types.h> /* pid_t */
#include <sys/mman.h> /* PROT_*, MAP_* — B6 pt_mmap output buffer */
#include <signal.h> /* SIGCONT — B6 pt_detach non-etaHEN requirement */
#include <dirent.h> /* opendir/readdir — r19.17 B6 user_id fallback via /user/home scan */
#include <sys/stat.h> /* stat — r19.39 trophy reset wipe recursive */

/* libNineS pt_* — ptrace primitives for cross-process call (Phase B6).
 * pt.h has no extern "C" wrapper of its own → must wrap from this side. */
extern "C" {
#include "pt.h"
int kill(pid_t pid, int sig); /* B6 — non-etaHEN PT_DETACH needs follow-up kill(SIGCONT) */
/* r19.39 — mkdir/chmod now declared via <sys/stat.h> include above (needed for stat) */
long write(int fd, const void *buf, size_t len); /* r16 B7 — file copy */
long lseek(int fd, long offset, int whence); /* r18 — file size for stat-skip */
}

/* libhijacker headers (C++) — needed for Hijacker::imagebase resolution */
#include "hijacker/hijacker.hpp"

/* prw::proc_read / prw::proc_write — DMAP primitives */
#include "proc_rw_v940.hpp"

extern "C" {
/* Underlying klog/diag functions. */
extern int klog_printf(const char *fmt,...);
extern void phu_diag_log(const char *fmt,...);

/* libNineS title-id-based proc lookup. Use this instead of libhijacker's
 * Hijacker::getHijacker(StringView name) because Sony's daemon p_comm fields
 * are unreliable / firmware-variant (e.g. SceShellUI's p_comm is actually
 * "SceShellUIMain" on 9.40, "SceShellUI" on 7.61, etc.). Title-id (NPXS*)
 * is stable across firmwares.
 * - NPXS40082 = SceShellCore (the trophy daemon, target of B1 patch)
 * - NPXS40087 = SceShellUI (the React-Native home UI, NOT the target)
 * libNineS struct proc has pid at offset 0xBC (validated 9.40). */
struct proc;
struct proc *get_proc_by_title_id(const char *title_id);
int phu_proc_get_pid(struct proc *p); /* defined below — wraps offset access */

/* PS5 payload SDK kstuff symbol resolvers — cross-process. Used by PHU's FPS
 * hook installer for libSceAgcDriver / libSceGnmDriver, and now by B2 for
 * libSceNpManager. More reliable than libhijacker's Hijacker::getLib on
 * processes whose SharedObject struct isn't yet fully populated (race at
 * game-detect time — B2-r5 KO: "Hijacker::getHijacker(pid=100) FAILED"). */
int kernel_dynlib_handle(pid_t pid, const char *basename, uint32_t *handle);
intptr_t kernel_dynlib_dlsym(pid_t pid, uint32_t handle, const char *sym);

/* r19.57 — sceUserServiceGetForegroundUser callable from probe context directly.
 * Linked at -lSceUserService (already used by phu_stats.c). Bypasses the
 * pt_call timing issue where the GAME process hasn't yet initialized
 * libSceUserService at trophy install time.
 *
 * r19.57 (post-runtime-diag) — also call sceUserServiceInitialize2 explicitly
 * because the probe process is a raw payload (elfldr-loaded ELF), unlike
 * SceShellUI where Sony's runtime auto-initializes it. Without the init,
 * all UserService queries return 0x80960002 NOT_INITIALIZED. */
int sceUserServiceGetForegroundUser(int *out);
int sceUserServiceInitialize2(void);

/* kernel_mprotect from ps5-payload-sdk — used to force TLB+µop cache flush
 * after a DMAP write to a.text page. The page protection is temporarily
 * "re-applied" (kept as PROT_RX) but the side effect is the kernel flushes
 * the cached instruction decode for that page, making the patched bytes
 * actually take effect on next CPU instruction fetch. */
int kernel_mprotect(pid_t pid, intptr_t addr, size_t size, int prot);
}

/* FreeBSD prot flags */
#ifndef PROT_READ
#define PROT_READ 0x01
#define PROT_WRITE 0x02
#define PROT_EXEC 0x04
#endif

/* Inline accessor: pid lives at offset 0xBC in libNineS' proc copy buffer
 * (TYPE_FIELD(int pid, 0xBC) in freebsd-helper.h). The libNineS layout is
 * a kernel-side raw buffer with C++-incompatible TYPE_BEGIN macro, accessed
 * via byte offset. */
extern "C" int phu_proc_get_pid(struct proc *p) {
    return p ? *(int *)(((char *)p) + 0xBC): -1;
}

/* Global config — defined in probe/source/main.cpp. C++ linkage but module
 * scope = no name mangling, so extern visible from this TU. */
extern phu_config_t g_phu_cfg;

/* SceShellUI pid baseline — set by phu_fps/main.cpp post-fork, used by
 * phu_recovery. Reuse the same source of truth here. */
extern pid_t g_probe_shellui_pid;

/* ============================================================================
 * r19.4 — Multi-firmware trophy support (data + stateless lookup helper)
 * ----------------------------------------------------------------------------
 * Per-fw offset table. On a matched fw, get_fw_offsets returns the entry
 * pointer and patch functions use e->xxx instead of hardcoded constants.
 *
 * Design intent: MINIMAL change vs r18b (validated runtime 9.40 trophy
 * install + unlock on 4 PS5 native games). Zero mutable globals, zero
 * lazy-init, zero ordering swap. Just a data table + a stateless lookup
 * function called once per patch operation. On 9.40, the helper returns
 * the "9.40" entry which contains the EXACT same constants as r18b — so
 * behavior on 9.40 is functionally identical to r18b.
 *
 * Adding a new fw: append a row to g_trophy_fw_table[] with RE'd
 * offsets. Beta testers grab klog/PHUdiag and crowd-source.
 *
 * RE source 9.40: SceShellCore.elf + libSceNpManager.sprx +
 * libSceNpTrophy2.sprx fw 9.40 (validated runtime 2026-05-13).
 * RE source 7.61: decompile 2026-05-13 (byte-exact
 * verified byte-exact; DAT shifted -0x10, anchor -0x330 vs 9.40;
 * libSceNpTrophy2 zero drift).
 * ============================================================================ */
typedef struct {
    const char *fw_label; /* matches phu_fw_offsets_t.fw_label — NOT encrypted */
    /* Plain uint64_t VAs (public source release). */
    uint64_t aaaa_slots[4]; /* B1 — AAAA00000 string slots (SceShellCore) */
    uint64_t crypto_bypass[2]; /* B3 — AES bypass funcs (SceShellCore) */
    uint64_t app_inventory_va; /* B4 — inventory wrapper func (SceShellCore) */
    uint64_t lnc_attr_va; /* B5_LNC — JZ patch site (SceShellCore) */
    uint64_t np_dat_offset; /* B2 — NpAsmClient singleton ptr offset in libSceNpManager.sprx */
    uint64_t np_anchor_offset; /* B2 — sceNpIntGetNpTitleIdSecret offset in libSceNpManager.sprx */
    uint64_t tr2_create_ctx_offset; /* B6 r15 — sceNpTrophy2CreateContext offset in libSceNpTrophy2.sprx */
    uint64_t tr2_dat_state_offset; /* B6 r15 — DAT client state ptr offset in libSceNpTrophy2.sprx */
    uint64_t b8_path_b_force_va; /* B8 — FUN_01d1c230 force-return-1 patch (SceShellCore).
                                      * r19.6 fix: on fw 10.01, Sony defaulted FUN_01d1c230's byte
                                      * flag at [arg+8] to 0 → trophy register takes path A
                                      * (FUN_01aede40 = B3-patched) → caller checks local_48
                                      * output → returns 0x8055390c. On 9.40 byte was 1 → path B
                                      * (FUN_01a8fc60) → B3 patches inert and trophy works.
                                      * Setting va=0 = no patch needed (fw already on path B).
                                      * Setting va=0x01d1c230 (10.01) patches to b8 01 00 00 00 c3
                                      * = `mov eax, 1; ret` → forces path B for all callers. */
    uint64_t b9_path_b_vtable_va; /* B9 — FUN_01d808a0 force-return-1 (SceShellCore). r19.8 fix:
                                      * after B8 forced path B (FUN_01a8fc60), path B has its OWN
                                      * vtable check `cVar2 = (*(*plVar6 + 0x10))(plVar6)` which
                                      * reads `*(byte*)(obj+0x70)` (= FUN_01d808a0). On 10.01 byte=0
                                      * → cVar2='\0' → return 0x8055d205 (observed runtime).
                                      * 9.40+7.61 = 0 (no patch needed, byte already 1 at runtime). */
    uint64_t b10_path_b_entry_va; /* B10 — FUN_01a8fc60 entry force success (SceShellCore). r19.8 fix:
                                      * even after B9, path B has 2 MORE failure modes:
                                      * (a) DAT_02f52010 NULL → 0x8055d202 (confirmed NULL in.bss
                                      * at load time on 10.01, init may not run during boot)
                                      * (b) inner vtable[5] slot+0x28 returns negative
                                      * Nuclear bypass: patch entry to `xor eax,eax; mov [rcx],rax;
                                      * ret` = 6 bytes → force return 0 + *param_4 = NULL.
                                      * Caller FUN_01d1c650 → FUN_01d1d450 handles NULL gracefully
                                      * (verified: `if (lVar1 != 0)` NULL checks before deref).
                                      * 9.40+7.61 = 0 (no patch, path B works natively on those fws). */
    uint64_t b5_auth_bypass_va; /* B5 — Debug auth bypass force return 1 (SceShellCore).
                                      * Patches FUN_019e84e0 (10.01) / FUN_019f0660 (9.40) to
                                      * `mov eax, 1; ret` (6 bytes) = always "has debug authority".
                                      * Enables Trophy 2 Debug APIs: sceNpTrophy2SystemDebugUnlock/
                                      * LockTrophy, RemoveAll/UserData/TitleData, GetTrophyData/Details,
                                      * ListAllTitles. r19.9: use this to call SystemDebugUnlockTrophy
                                      * directly per trophy_id = bypass RegisterContext entirely
                                      * on 10.01 where path A+B are deprecated.
                                      * Original prologue: 55 48 89 e5... (push rbp; mov rbp,rsp)
                                      * Patch: b8 01 00 00 00 c3 (6 bytes, overwrites prologue start).
                                      * KP risk note: enables all Debug APIs in daemon — historically
                                      * skipped for safety on 9.40. r19.9 re-enables for 10.01
                                      * because path A+B dead = need DebugUnlock as primary path. */
    uint64_t b12_commid_force_va; /* B12 — FUN_01d1c520 NOP JZ surgical (r19.16 SAFE version).
                                      * r19.15 attempted to patch FUN_01d1d320 universally → crashed
                                      * beta tester console (other consumers deref'd fake value 1
                                      * as a pointer → kernel panic).
                                      *
                                      * r19.16 surgical: patch ONLY the JZ at 0x01d1c5ca inside
                                      * FUN_01d1c520 that branches to the 0x8055391a error path.
                                      * Original: 74 6A (JZ short +0x6A)
                                      * Patch: 90 90 (NOP NOP, 2 bytes)
                                      *
                                      * Effect: if commId is NULL, execution falls through to the
                                      * success path which stores local_40 (= BindInfo ptr) in output.
                                      * No effect on FUN_01d1d320 itself — keeps original behavior
                                      * for ALL other Sony callers → no cross-fn side effects.
                                      *
                                      * VA passed here is the JZ site (0x01d1c5ca on 10.01).
                                      * 9.40+7.61 = 0 (no patch needed). */
    uint64_t b18_force_firsttime_va; /* B18 r19.23 — Force first-time path in FUN_01a6fcc0
                                      * (the IpcJob RegisterContext orchestrator).
                                      * RE 2026-05-14 mapped the full chain:
                                      * Client IPMI 0x90016 → SceShellCore FUN_01cd4e90 (handler)
                                      * → submits RegisterContextIpcJob (FUN_01cd50f0 ctor)
                                      * → async Execute → FUN_01a6f610 (mask wrapper) →
                                      * FUN_01a709e0 → FUN_01a6fcc0 (THE ORCHESTRATOR).
                                      * FUN_01a6fcc0 branches on state byte cVar1 @ ctx+0x3d:
                                      * - cVar1==0 → first-time path (SWALLOWS 0x8055391e
                                      * via CMOVNZ @ 0x01a7037b-0x01a70386) → return 0
                                      * - cVar1!=0 → else path → no swallow → propagates
                                      * B18 surgical 3-byte patch: @ 0x01a6fd0a, replace
                                      * TEST R12B,R12B (45 84 E4) → XOR R12B,R12B (45 30 E4)
                                      * Effect: ZF=1 always → JZ @ 0x01a6fd0d always taken →
                                      * first-time path forced → 0x8055391e/0x8055391a/etc.
                                      * swallowed via CMOVNZ → return 0 success.
                                      * 9.40/7.61 = 0 (no patch needed). */
    uint64_t b20_isdeprecated_va; /* B20 r19.39 — Bypass IsDeprecatedVersion gate (FUN_01a9f010
                                      * on 4.03). Sony's CreateUserDataFile initializes the
                                      * user_data_file version field at +0x68 with 0x10000,
                                      * then IsDeprecatedVersion checks (*(p+0x68) == 0x10000)
                                      * which returns TRUE — meaning by-design ALL freshly
                                      * created files are "deprecated" on 4.03 launch fw.
                                      * Cascade: UpdateSummaryFile gate (FUN_01a9d0f0)
                                      * fires DELETE path → trpsummary.dat never updated →
                                      * profile shows 0/0/0/0 trophies. Bug Sony fixed in
                                      * later fws via version upgrade.
                                      * Patch: 3 bytes overwrite entry with `31 C0 C3`
                                      * (XOR EAX, EAX; RET) → always returns FALSE.
                                      * Only 4.03 needs this (other fws version != 0x10000).*/
    uint64_t b21_recovery_setter_va; /* B21 r19.39 — Disable RecoveryRequired flag setter
                                      * (FUN_01aa0150 on 4.03). Called by CreateUserDataFile
                                      * when local_39 != 0, reads NPWR entry first uint from
                                      * trophy.img header @ +0x6c, then writes back with
                                      * bit 0 set: local_58 = htonl(uVar2 | 1). This sets
                                      * "RecoveryRequired" flag on the entry.
                                      * Cascade: UpdateSummaryFile gate's first condition
                                      * `local_a1 != 0` reads this bit → if set → DELETE
                                      * summary path.
                                      * Patch: 3 bytes overwrite entry with `31 C0 C3`
                                      * (XOR EAX, EAX; RET) → no flag set on new entries.
                                      * Only 4.03 needs this. */
    uint64_t b22_recovery_read_va; /* B22 r19.55 NEW — RecoveryRequired READER bypass.
                                      * Critical companion to B21. Even if B21 prevents
                                      * FUTURE writes of the recovery flag, files created
                                      * by previous broken installs have flag=1 PERSISTED
                                      * on disk @ +0x6c. This reader (FUN_01aa02b0 on 4.03 /
                                      * FUN_01aa0c20 on 4.50) reads the flag from disk via
                                      * FUN_01a90450(file,..., +0x6c,..., 0x30) then sets
                                      * *param_3 = (htonl_result & 1).
                                      * Called by UpdateSummaryFile (= gate trigger site) AND
                                      * GetRecoveryRequired (external API). Without B22, any
                                      * pre-existing on-disk flag=1 still triggers DELETE
                                      * path → trpsummary wiped → unlock silent fail (= the
                                      * beta tester 4.03 "trophées profil OK mais unlock
                                      * broken" symptom).
                                      * Patch (5 bytes): `31 C0 88 02 C3`
                                      * (XOR EAX, EAX; MOV [RDX], AL; RET) →
                                      * always returns 0 + writes 0 to *param_3.
                                      * 4.x range only (4.03/4.50). Other fws: VA=0 = skip. */
} phu_trophy_fw_offsets_t;

static const phu_trophy_fw_offsets_t g_trophy_fw_table[] = {
    /* 9.00 — Sony build dir J03113952. Pre-Cronos hybrid era (like 5.02/5.50/6.02/6.50/8.00/9.60):
     * Cronos infrastructure compiled (AppSubcontainerPrepareNpForCronos + np_bind_dat2_file.cpp
     * strings PRESENT) but runtime sceKernelIsCronos returns 0 → file_loader path active.
     * Patching B3 sabotages file loaders (= sentinel returns 2 pre-Cronos branch, gate passes
     * for B7+B2+B6). B1 ×4 byte-exact == 9.40 (.rodata SceShellCore unchanged 9.00→9.40).
     * libSceNpManager + libSceNpTrophy2 byte-identical to 9.40 (B2 DAT 0x63128 + anchor 0x15310,
     * B6 0x150 + 0x18080). B5_LNC attr offset = +0x104 (pre-Cronos style, NOT 9.40 +0xd4 Cronos
     * style). B4 wrapper shifted -0x30 vs 9.40 (FUN_01726690 vs 9.40's 0x017266c0).
     * Reference: getSceSysDirPath FUN_015da710 line 0xa3f, lnc_manager.cpp. */
    { "9.00",
      { 0x02e7f488UL, 0x02e7f494UL, 0x02e7fbe8UL, 0x02e7fbf4UL },
      { 0UL, 0UL }, /* B3 DISABLED — hybrid era, FUN_01a9df30 is allocator/object-builder NOT crypto stub (verified byte-exact). Sentinel return 2 pre-Cronos branch */
      0x01726690UL, 0x015da91aUL, /* B4 wrapper FUN_01726690 (-0x30 vs 9.40); B5_LNC JZ position 0x015da91a (TEST [RSI+0x104] +0x104 pre-Cronos style + JZ short, NOP-insensitive) */
      0x63128UL, /* libSceNpManager DAT_01063128 byte-exact == 9.40 (NULL.bss confirmed) */
      0x15310UL, /* libSceNpManager sceNpIntGetNpTitleIdSecret @ 0x01015310 byte-exact == 9.40 (16-byte tail-thunk) */
      0x150UL, /* libSceNpTrophy2 sceNpTrophy2CreateContext (★ stable cross-fw) */
      0x18080UL, /* libSceNpTrophy2 DAT_01018080 client state (★ stable cross-fw) */
      0UL, /* B8 DISABLED — pre-Cronos era */
      0UL, /* B9 DISABLED */
      0UL, /* B10 DISABLED */
      0UL, /* B5_auth DISABLED */
      0UL, /* B12 DISABLED */
      0UL, /* B18 DISABLED */
      0UL, /* B20 NOT needed on 9.00 (Sony fixed IsDeprecatedVersion in later pre-Cronos) */
      0UL, /* B21 NOT needed on 9.00 */
      0UL /* B22 NOT needed on 9.00 */
    },
    /* 9.40 — validated runtime 4 PS5 native games (Astro Bot trophy install + unlock confirmed). */
    { "9.40",
      { 0x02e7f488UL, 0x02e7f494UL, 0x02e7fbe8UL, 0x02e7fbf4UL },
      { 0x01a9dfe0UL, 0x01a9fe50UL },
      0x017266c0UL, 0x015dad0aUL,
      0x63128UL, /* libSceNpManager DAT_01063128 - 0x01000000 */
      0x15310UL, /* libSceNpManager sceNpIntGetNpTitleIdSecret offset */
      0x150UL, /* libSceNpTrophy2 sceNpTrophy2CreateContext offset */
      0x18080UL, /* libSceNpTrophy2 DAT_01018080 client state offset */
      0, /* B8 NOT needed on 9.40 (runtime byte = 1 already, path B default) */
      0, /* B9 NOT needed on 9.40 (vtable byte = 1 already) */
      0, /* B10 NOT needed on 9.40 (path B works natively) */
      0, /* B5 disabled on 9.40 (RegisterContext works without DebugUnlock fallback) */
      0, /* B12 NOT needed on 9.40 (Path A produces valid commId via AES decrypt) */
      0, /* B18 NOT needed on 9.40 (state byte correctly 0 → first-time path → swallow) */
      0, /* B20 NOT needed on 9.40 (Sony fixed IsDeprecatedVersion in later fws) */
      0, /* B21 NOT needed on 9.40 */
      0UL /* B22 NEW r19.55 — RecoveryRequired reader bypass (4.x only) */
    },
    /* 9.60 — RE 2026-05-19 (Sony build dir J03308751, between 9.40 and 10.01).
     * Architecture HYBRID pre-Cronos (= comme 5.02/5.50/6.50/8.00 hybrid pattern):
     * - Cronos infrastructure compiled (AppSubcontainerPrepareNpForCronos +
     * sceKernelIsCronos + np_bind_dat2_file.cpp strings PRESENT)
     * - But runtime sceKernelIsCronos returns 0 on retail 9.60 → Cronos branch
     * not taken at runtime → file_loader path actif (= sabotage si B3 ENABLE)
     * - Solution: B3 DISABLED (sentinel returns 2 → gate passes for B7+B2+B6
     * en pre-Cronos branch)
     * - LNC attr offset = +0x104 (NOT +0xd4 comme 9.40), même qu'on a vu sur
     * 4.03/5.02/5.50/6.50. B5_LNC patch site avec SHORT JZ `74 1A` (= 9.40 style).
     * - libSceNpManager.sprx 9.60 byte-identical avec 9.40 (verified byte-exact):
     * DAT @ 0x63128, anchor @ 0x15310 — drop-in compat.
     * - libSceNpTrophy2.sprx 9.60 byte-identical avec 9.40: 0x150 + 0x18080 stable.
     *
     * Byte-exact verified:
     * - B1 ×4 AAAA strings @ 0x02e8b488/494/be8/bf4 (+0xC000 vs 9.40 shift.rodata)
     * - B5_LNC @ 0x015dad7a (+0x70 vs 9.40), pre-bytes `f6 86 04 01 00 00 06 74 1A`
     * (TEST [RSI+0x104],0x6 + JZ short — hybrid pattern: old attr offset + short JZ moderne)
     *
     * KISS first ship: B4 disabled. SceShellCore reorganisée vs 9.40 → wrapper
     * 3-arg `(uint cat, char *tid, undefined8 *out)` non identifié à coup sûr.
     * Beta runtime révèlera si B4 nécessaire. Skip-if-zero handling déjà en place. */
    { "9.60",
      { 0x02e8b488UL, 0x02e8b494UL, 0x02e8bbe8UL, 0x02e8bbf4UL },
      { 0UL, 0UL }, /* B3 DISABLED — hybrid pattern, sentinel returns 2 for pre-Cronos B7+B2+B6 gate */
      0UL, 0x015dad7aUL, /* B4 disabled first ship (wrapper refactored, TBD if needed); B5_LNC short JZ @ 0x015dad7a (attr offset +0x104) */
      0x63128UL, /* libSceNpManager DAT (= byte-identical avec 9.40) */
      0x15310UL, /* libSceNpManager anchor (= byte-identical avec 9.40) */
      0x150UL, /* libSceNpTrophy2 CreateContext (★ stable cross-fw) */
      0x18080UL, /* libSceNpTrophy2 DAT_01018080 (★ stable cross-fw) */
      0UL, /* B8 NOT needed on 9.60 (pre-Cronos hybrid, like 9.40) */
      0UL, /* B9 NOT needed */
      0UL, /* B10 NOT needed */
      0UL, /* B5_auth disabled */
      0UL, /* B12 NOT needed */
      0UL, /* B18 NOT needed */
      0UL, /* B20 NOT needed (Sony fixed IsDeprecatedVersion since 5.50+) */
      0UL, /* B21 NOT needed */
      0UL /* B22 NEW r19.55 — RecoveryRequired reader bypass (4.x only) */
    },
    /* 8.00 — RE 2026-05-15. Pre-Cronos (8.0 < 10.x)
     * → daemon non-Cronos branch → /system_data/priv/appmeta/ path like 9.40/7.61.
     * Pattern 9.40-baseline (B1+B3+B4+B5_LNC + np offsets + tr2 offsets, no B11/B13-B16).
     * AppSubcontainerPrepareNpForCronos string EXISTS in 8.0 binary but sceKernelIsCronos
     * returns 0 → Cronos branch not taken at runtime. B7 fills /priv/appmeta/. */
    { "8.00",
      { 0x02daf448UL, 0x02daf454UL, 0x02dafba8UL, 0x02dafbb4UL },
      /* r19.31 — B3 DISABLED on 8.00: beta tester runtime r19.30 confirmed
       * RegisterContext rc=0x8055390c after CreateContext/CreateHandle success.
       * Same root cause as 10.01: Path A default → B3 patches file loader →
       * output NULL → 0x8055390c. 8.00 takes Path A like 10.01 (unlike 9.40
       * which uses Path B). r19.31 disables B3 + extends do_crypto_bypass_patch
       * to return 2 (= "done") when va==0, so B7 still runs (gate passes). */
      { 0UL, 0UL }, /* B3 DISABLED */
      0x016e3970UL, 0x015a5f53UL, /* B4 = FUN_016e3970; B5_LNC site at attr & 6 JZ */
      0x63128UL, /* libSceNpManager DAT_01063128 (identical 9.40) */
      0x15350UL,/* libSceNpManager sceNpIntGetNpTitleIdSecret offset (+0x40 vs 9.40) */
      0x150UL, /* libSceNpTrophy2 sceNpTrophy2CreateContext (identical 9.40) */
      0x18080UL, /* libSceNpTrophy2 DAT_01018080 client state (identical 9.40) */
      0UL, /* B8 NOT needed on 8.00 (pre-Cronos, Path B default) */
      0UL, /* B9 NOT needed on 8.00 */
      0UL, /* B10 NOT needed on 8.00 */
      0UL, /* B5_auth disabled */
      0UL, /* B12 NOT needed on 8.00 */
      0UL, /* B18 NOT needed on 8.00 */
      0UL, /* B20 NOT needed on 8.00 (Sony fixed IsDeprecatedVersion) */
      0UL, /* B21 NOT needed on 8.00 */
      0UL /* B22 NEW r19.55 — RecoveryRequired reader bypass (4.x only) */
    },
    /* 4.03 — RE 2026-05-15. Pre-Cronos oldest supported fw.
     * Pattern 9.40-baseline (B1+B3+B4+B5_LNC + np offsets + tr2 offsets).
     * Key differences vs 9.40:
     * - NpManager DAT @ 0x57028 (not 0x63128 — older lib layout)
     * - B5_LNC uses LONG JZ `0F 84 86 00 00 00` (6 bytes, vs short `74 1A` on 9.40)
     * → do_lnc_attr_bypass_patch auto-detects via pre-byte signature.
     * - AppSubcontainerPrepareNpForCronos string DOES NOT exist on 4.03 (= no Sony
     * auto-prepare infrastructure yet) → B7 file copy MUST run to populate
     * /system_data/priv/appmeta/<TID>/.
     * - Trophy2 ABI identical (CreateContext 0x150, DAT state 0x18080). */
    { "4.03",
      { 0x029f7108UL, 0x029f7114UL, 0x029f7868UL, 0x029f7874UL },
      /* r19.35 — B3 DISABLED on 4.03: runtime test PPSA04048 (LEGO 2K Drive)
       * confirmed RegisterContext rc=0x8055390c (= same B3 sabotage pattern as
       * 8.00 and 10.01). The B3 VAs probably patch a file loader on 4.03 (not
       * a crypto stub like 9.40/7.61), so the patch shortcircuits npbind.dat
       * loading → daemon's commit chain returns 0x8055390c. Disable B3:
       * do_crypto_bypass_patch sentinel returns 2 ("done") for pre-Cronos so
       * B7+B2+B6 gate continues. 4.03 doesn't have Cronos auto-prepare, so
       * B7 file copy must run (per pre-Cronos pattern). */
      { 0UL, 0UL }, /* B3 DISABLED — was {0x0187ada0, 0x0187ad00} (file loader sabotage) */
      0x0155d5b0UL, 0x0143db4cUL, /* B4 = FUN_0155d5b0; B5_LNC site long JZ 0F 84 86 00 00 00 */
      0x57028UL, /* libSceNpManager DAT_01057028 (older layout, different from 9.40 0x63128) */
      0x150e0UL, /* libSceNpManager sceNpIntGetNpTitleIdSecret @ 0x010150e0 */
      0x150UL, /* libSceNpTrophy2 sceNpTrophy2CreateContext (identical 9.40) */
      0x18080UL, /* libSceNpTrophy2 DAT_01018080 client state (identical 9.40) */
      0UL, /* B8 NOT needed on 4.03 (pre-Cronos) */
      0UL, /* B9 NOT needed on 4.03 */
      0UL, /* B10 NOT needed on 4.03 */
      0UL, /* B5_auth disabled */
      0UL, /* B12 NOT needed on 4.03 */
      0UL, /* B18 NOT needed on 4.03 */
      /* r19.43 — B20+B21 DISABLED on 4.03 default ship.
       *
       * Original hypothesis (r19.39): Sony 4.03 launch fw IsDeprecatedVersion
       * check (version == 0x10000) was causing UpdateSummaryFile DELETE forever.
       * Verified byte-exact via RE.
       *
       * But runtime test 2026-05-17 on Arksama 4.03 console showed:
       * - Trophy display WORKED BEFORE FTP wipe (= 4.03 baseline OK)
       * - Trophy display BROKEN AFTER FTP wipe + Safe Mode Rebuild (= cascade panic)
       * - B20+B21 patches applied at runtime but trpsummary still empty
       * = B20+B21 do NOT fix the cascade panic Sony state corruption
       *
       * Conclusion: 4.03 baseline trophy display works WITHOUT B20+B21.
       * Cascade panic from FTP delete recursive = Sony state corruption
       * non-recoverable without factory reset. B20+B21 = dead code patch
       * for fresh users (= no-op since gate already FALSE on baseline).
       *
       * B20+B21 VAs zeroed out by default. Code paths kept for experimental
       * opt-in via cfg trophy_summary_bypass_enabled if user has specific bug.
       * Original VAs documented: B20 = 0x01a9f010, B21 = 0x01aa0150. */
      /* r19.55 — TRIO B20+B21+B22 RE-ENABLED par défaut. La décision r19.43 de
       * disable était basée sur cascade panic console test, où le bug n'était PAS
       * dans le code PHU mais dans la corruption Sony state. Pour fresh users 4.03
       * launch fw (= beta tester scenario), le trio est CRITIQUE pour fix le
       * "trophées affichent profil mais ne se débloquent pas en jeu" symptom.
       *
       * Le trio est nécessaire car les 3 patches sont symbiotiques:
       * - B20 alone: B21 still poisons file via UpdateTitleEntry failure path
       * - B21 alone: pre-existing on-disk flag still triggers DELETE path
       * - B22 NEW: force read flag=0 unconditionally (final piece)
       *
       * Per RE 2026-05-20 deep verification:
       * - FUN_01a9f010 IsDeprecatedVersion: prologue 55 48 89 e5 53 50 4889 fb (verified)
       * - FUN_01aa0150 RecoveryRequired setter: prologue 55 48 89 e5 41 57 41 56 53 (verified)
       * - FUN_01aa02b0 RecoveryRequired reader: prologue 55 48 89 e5 41 57 41 56 53 (verified)
       * B22 patch 5 bytes `31 C0 88 02 C3` (xor eax,eax; mov [rdx],al; ret)
       * overwrites first 5 bytes → returns 0 + writes 0 to *param_3 (out flag).
       *
       * Cfg `trophy_summary_bypass_enabled` reste honoré (= user peut disable). */
      0x01a9f010UL, /* B20 RE-ENABLED — FUN_01a9f010 IsDeprecatedVersion */
      0x01aa0150UL, /* B21 RE-ENABLED — FUN_01aa0150 RecoveryRequired setter */
      0x01aa02b0UL /* B22 NEW — FUN_01aa02b0 RecoveryRequired reader bypass */
    },
    /* 4.50 — RE deep verification 2026-05-20 (Sony build dir J01795075,
     * between 4.03 J01736823 and 5.02 J02014101 — early PS5 launch fw range).
     *
     * Architecture PRE-CRONOS HYBRID (like 4.03 / 5.50 / 6.50 / 8.00):
     * - `np_bind_dat_file.cpp` + `np_bind_dat2_file.cpp` PRESENT (v1 + v2 file loaders)
     * - `sceKernelIsCronos` string PRESENT @ 0x027e87b7 (Cronos check compiled)
     * - `AppSubcontainerPrepareNpForCronos` ABSENT (no auto-prepare on 4.x)
     * - → B3 sites are FILE LOADERS (sabotage if patched, like 4.03/5.50)
     *
     * libSceNpManager.sprx 4.50 IDENTICAL architecture à 4.03:
     * - sceNpIntGetNpTitleIdSecret @ 0x010150e0 (= same as 4.03)
     * - FUN_010298a0 singleton getter returns DAT_01057028 (= same as 4.03)
     * - Older lib layout (393 KB vs 9.40 475 KB)
     *
     * libSceNpTrophy2.sprx 4.50 BYTE-IDENTICAL to 9.40 ABI:
     * - sceNpTrophy2CreateContext @ 0x01000150 (★ stable cross-fw)
     * - DAT_01018080 client state (★ stable cross-fw)
     *
     * Byte-exact verified:
     * - B1 ×4 AAAA strings @ 0x02a03108/114/868/874
     * - B5_LNC @ 0x0143e29c LONG JZ `0F 84 86 00 00 00` (= same form as 4.03/5.50/6.50)
     * - B5_LNC attr offset = +0x104 (= same as 4.03)
     *
     * KISS minimal set (= mirror 4.03 row pattern): B1+B3 disabled+B5_LNC+B2+B6.
     * B4 disabled first ship (wrapper not strictly RE'd yet).
     * B20+B21 disabled by default (same r19.43 reasoning as 4.03 — opt-in cfg).
     * Beta runtime tester will reveal if 4.x range needs B20+B21+B22 trio fix
     * (= "trophées affichent profil mais unlock broken" pattern reported on 4.03). */
    { "4.50",
      { 0x02a03108UL, 0x02a03114UL, 0x02a03868UL, 0x02a03874UL },
      { 0UL, 0UL }, /* B3 DISABLED — file loader sabotage like 4.03/5.50 */
      0UL, 0x0143e29cUL, /* B4 disabled first ship; B5_LNC LONG JZ 0F 84 86 00 00 00 @ 0x0143e29c (attr offset +0x104) */
      0x57028UL, /* libSceNpManager DAT_01057028 (= same as 4.03 older layout, verified via FUN_010298a0 singleton getter) */
      0x150e0UL, /* libSceNpManager sceNpIntGetNpTitleIdSecret @ 0x010150e0 (= same as 4.03) */
      0x150UL, /* libSceNpTrophy2 sceNpTrophy2CreateContext (★ stable cross-fw) */
      0x18080UL, /* libSceNpTrophy2 DAT_01018080 client state (★ stable cross-fw) */
      0UL, /* B8 NOT needed on 4.50 (pre-Cronos) */
      0UL, /* B9 NOT needed */
      0UL, /* B10 NOT needed */
      0UL, /* B5_auth disabled */
      0UL, /* B12 NOT needed */
      0UL, /* B18 NOT needed */
      0UL, /* B20 disabled-by-default (opt-in cfg) — RE'd VA byte-exact 2026-05-24: FUN_01a9f980 (IsDeprecatedVersion `*(int*)(param_1+0x68) == 0x10000`, build dir J01795075) */
      0UL, /* B21 disabled-by-default — RE'd VA byte-exact 2026-05-24: FUN_01aa0ac0 (SetRecoveryRequired = htonl(uVar | 1) write back) */
      0UL /* B22 disabled-by-default — RE'd VA byte-exact 2026-05-24: FUN_01a9e5a0 (GetRecoveryRequired wrapper for FUN_01aa0c20) */
    },
    /* 4.51 — RE deep verification 2026-05-24 (Sony build dir J01948388,
     * between 4.50 J01795075 and 5.02 J02014101 — launch fw hotfix).
     *
     * Architecture QUASI-HOTFIX of 4.50:
     * - 6/8 SceShellCore offsets BYTE-IDENTICAL to 4.50 (B1 ×4, B5_LNC, B2 anchor)
     * - libSceNpManager / libSceNpTrophy2 ABI unchanged (B2 DAT 0x57028, B6 0x150/0x18080)
     * - Only trio area shifted +0x10 (= small recompile, function reordering)
     *
     * Same Sony bug pre-Cronos confirmed byte-exact via RE:
     * - FUN_01a9f990 IsDeprecatedVersion: `return *(int *)(param_1 + 0x68) == 0x10000;`
     * (= IDENTICAL bug pattern as 4.03 — launch fw value always TRUE)
     * - FUN_01a9e5b0 GetRecoveryRequired: reader wrapper for FUN_01aa0c30
     * - FUN_01aa0ad0 SetRecoveryRequired = 1 setter (= htonl(uVar | 1) write back)
     *
     * Trio B20+B21+B22 DISABLED par défaut (= mirror 4.50 r19.43 logic).
     * User opt-in via cfg trophy_summary_bypass_enabled if beta tester reports
     * "trophies show in profile but unlock broken in-game" symptom (= same as
     * 4.03 r19.55 scenario). VAs documented for runtime activation. */
    { "4.51",
      { 0x02a03108UL, 0x02a03114UL, 0x02a03868UL, 0x02a03874UL },
      { 0UL, 0UL }, /* B3 DISABLED — file loader sabotage like 4.03/4.50 */
      0UL, 0x0143e29cUL, /* B4 disabled first ship; B5_LNC LONG JZ 0F 84 86 00 00 00 @ 0x0143e29c (= identical 4.50) */
      0x57028UL, /* libSceNpManager DAT_01057028 (= identical 4.03/4.50 older layout) */
      0x150e0UL, /* libSceNpManager sceNpIntGetNpTitleIdSecret @ 0x010150e0 (= identical 4.50) */
      0x150UL, /* libSceNpTrophy2 sceNpTrophy2CreateContext (★ stable cross-fw) */
      0x18080UL, /* libSceNpTrophy2 DAT_01018080 client state (★ stable cross-fw) */
      0UL, /* B8 NOT needed on 4.51 (pre-Cronos) */
      0UL, /* B9 NOT needed */
      0UL, /* B10 NOT needed */
      0UL, /* B5_auth disabled */
      0UL, /* B12 NOT needed */
      0UL, /* B18 NOT needed */
      0UL, /* B20 disabled-by-default (opt-in cfg, mirror 4.50 r19.43 logic) — RE'd VA = FUN_01a9f990 (IsDeprecatedVersion `*(int*)(param_1+0x68) == 0x10000`) */
      0UL, /* B21 disabled-by-default — RE'd VA = FUN_01aa0ad0 (SetRecoveryRequired = htonl(uVar | 1) write back) */
      0UL /* B22 disabled-by-default — RE'd VA = FUN_01a9e5b0 (GetRecoveryRequired wrapper for FUN_01aa0c30) */
    },
    /* 5.50 — RE 2026-05-15 + r19.44 deep audit 2026-05-18.
     * Pre-Cronos between 4.03 and 7.61, SAME ARCHITECTURE as 4.03/5.02/6.50.
     *
     * r19.44 CRITICAL FIX: B3 DISABLED (was {0x0192e770, 0x0192e840}).
     * decompile 2026-05-18 confirmed both B3 targets are FILE LOADERS
     * (LocalFilePath local_60[40] + sceKernelIsCronos check + FUN_0192eee0
     * np_bind_dat2_file parser), NOT crypto stubs. Patching them with
     * `xor eax;ret` makes them return 0 but `*param_6` stays NULL → caller
     * cascade returns 0x8055390c (= same SABOTAGE pattern as 4.03 r19.35).
     *
     * Conclusion: 5.50 = 4ème fw KISS minimal pre-Cronos (after 4.03/5.02/6.50).
     * Sentinel `crypto_bypass={0,0}` returns 2 → gate passes for B7+B2+B6.
     *
     * Key offsets:
     * - B5_LNC uses LONG JZ `0F 84 86 00 00 00` @ 0x014a5d9c (auto-detected)
     * - LNC attr offset = +0x104 (verified `F6 86 04 01 00 00 06`, like 5.02/6.50)
     * - NpManager DAT 0x630e8 ✅ VERIFIED BYTE-EXACT r19.44 via RE
     * on libSceNpManager.sprx 5.50: NULL.bss + FUN_0102d3f0 ctor WRITE.
     * Sony genuinely expanded libSceNpManager on 5.50 (PT_LOAD added
     * segment 0x60000-0x6324D ~12KB extra.bss singletons) then reduced
     * back on 6.50+. Pattern outlier confirmed, NOT a wrong RE.
     * - NpManager anchor 0x14ef0 ✅ = sceNpIntGetNpTitleIdSecret confirmed
     * via RE symbol name (= thin wrapper for sceNpAsmClientGetNpTitleId).
     * - Trophy2 ABI identical (CreateContext 0x150, DAT state 0x18080). */
    { "5.50",
      { 0x02a9f318UL, 0x02a9f324UL, 0x02a9fa78UL, 0x02a9fa84UL },
      { 0UL, 0UL }, /* r19.44 B3 DISABLED — was {0x0192e770, 0x0192e840} (file loader sabotage like 4.03) */
      0x015ca5d0UL, 0x014a5d9cUL, /* B4 = FUN_015ca5d0 (valid wrapper); B5_LNC site long JZ 0F 84 86 00 00 00 */
      0x630e8UL, /* libSceNpManager DAT_010630e8 (different from 9.40 0x63128) */
      0x14ef0UL, /* libSceNpManager sceNpIntGetNpTitleIdSecret @ 0x01014ef0 */
      0x150UL, /* libSceNpTrophy2 sceNpTrophy2CreateContext (identical 9.40) */
      0x18080UL, /* libSceNpTrophy2 DAT_01018080 client state (identical 9.40) */
      0, /* B8 NOT needed on 5.50 (pre-Cronos) */
      0, /* B9 NOT needed on 5.50 */
      0, /* B10 NOT needed on 5.50 */
      0, /* B5_auth disabled */
      0, /* B12 NOT needed on 5.50 */
      0, /* B18 NOT needed on 5.50 */
      0, /* B20 TBD on 5.50 (need RE — likely Sony also has this bug, set if confirmed) */
      0, /* B21 TBD on 5.50 */
      0UL /* B22 NEW r19.55 — RecoveryRequired reader bypass (4.x only) */
    },
    /* 5.02 — RE 2026-05-17.
     * Pre-Cronos era between 5.00 and 5.10. Cronos infrastructure partially
     * compiled (only 1 string `license_dat_not_found` vs 2 on 6.50/8.00), so
     * sceKernelIsCronos returns 0 at runtime = pure pre-Cronos behavior.
     *
     * Sony build dir: J02014101 (oldest of the supported fws).
     *
     * SAME pattern as 6.50:
     * - B5_LNC LONG JZ pattern (`0F 84 86 00 00 00` 6 bytes) → 6× NOP patch
     * - LNC attr offset @ +0x104 (NOT +0xd4 like 7.61+)
     * - libSceNpManager UNCHANGED (B2 DAT @ 0x5d1c0 stable)
     * - libSceNpTrophy2 UNCHANGED (B6 0x150 + 0x18080 stable)
     * - IsDeprecatedVersion EXISTS but B20+B21 disabled (= safe pre-Cronos)
     *
     * KISS minimal: B1+B5_LNC+B6+B2 DAT (B3+B4 disabled first ship).
     * NOT in is_cronos branch (= sentinel returns 2 pre-Cronos pattern).
     *
     * B17 cluster RE'd: FUN_01ae1ed0 body 0x01ae1ed0-0x01ae21d6 (5×MOV
     * 0x8055391e at 0x01ae205f/66/19e/1c2/1cc) — gated 10.01-only in code. */
    { "5.02",
      { 0x02a97318UL, 0x02a97324UL, 0x02a97a78UL, 0x02a97a84UL },
      { 0, 0 }, /* B3 DISABLED first ship */
      0UL, 0x014a3e6cUL, /* B4 disabled; B5_LNC LONG JZ 0F 84 86 00 00 00 @ 0x014a3e6c */
      0x5d1c0UL, /* libSceNpManager DAT_0105d1c0 (SAME as 6.50/11.20/11.60) */
      0UL, /* B2 anchor TBD */
      0x150UL, /* libSceNpTrophy2 sceNpTrophy2CreateContext (★ stable) */
      0x18080UL, /* libSceNpTrophy2 DAT_01018080 (★ stable) */
      0, 0, 0, 0, 0, 0, /* B8-B18 disabled */
      0, 0, /* B20+B21 disabled (safe pre-Cronos) */
      0UL /* B22 NEW r19.55 — RecoveryRequired reader bypass (4.x only) */
    },
    /* 6.50 — RE 2026-05-17.
     * Pre-Cronos era between 5.50 and 7.61. Cronos infrastructure compiled in
     * binary (np_bind_dat2_file + AppSubcontainerPrepareNpForCronos strings +
     * sceKernelIsCronos check) but probably DORMANT at runtime (= hybrid pattern
     * like 8.00, sceKernelIsCronos returns 0 on pre-Cronos retail fws).
     *
     * Sony build dir: J02466812 (older than 11.x J03595639/J03675035).
     *
     * Key differences vs other fws:
     * - B5_LNC uses LONG JZ (like 4.03/5.50) bytes `0F 84 86 00 00 00`
     * → 6-byte patch (vs 2-byte short JZ on 7.61+/Cronos)
     * - LNC offset CHANGED: attr field @ +0x104 (not +0xd4 like recent fws)
     * bytes `f6 86 04 01 00 00 06` (vs `f6 86 d4 00 00 00 06` on 11.x+)
     * - libSceNpManager UNCHANGED (B2 DAT @ 0x5d1c0 same as 11.20/11.60)
     * - libSceNpTrophy2 UNCHANGED (B6 0x150 + 0x18080 stable cross-fw)
     * - IsDeprecatedVersion EXISTS (string @ 0x0296407b) — possibly same Sony
     * bug as 4.03 launch fw, but TBD if version field stored matches 0x10000
     *
     * KISS minimal set: B1+B5_LNC+B6+B2 DAT. B3+B4 disabled first ship.
     * Sentinel `crypto_bypass={0,0}` returns 2 (= pre-Cronos pattern, gate passes
     * for B7+B2+B6 continuation). NOT added to is_cronos branch (= 6.50 takes
     * non-Cronos path in do_crypto_bypass_patch).
     *
     * B17 cluster RE'd: FUN_01b367b0 body 0x01b367b0-0x01b36ab6 (5× MOV
     * 0x8055391e at 0x01b3693f/46/a7e/aa2/aac) — but gated 10.01-only in code
     * so NOT applied on 6.50. */
    { "6.50",
      { 0x02b5b398UL, 0x02b5b3a4UL, 0x02b5baf8UL, 0x02b5bb04UL },
      { 0, 0 }, /* B3 DISABLED first ship (crypto stubs TBD) */
      0UL, 0x014d3c5cUL, /* B4 disabled; B5_LNC LONG JZ 0F 84 86 00 00 00 @ 0x014d3c5c */
      0x5d1c0UL, /* libSceNpManager DAT_0105d1c0 (= SAME as 11.20/11.60) — ⚠ r19.57 audit revealed this = PTR___stack_chk_guard (= stack canary), NOT NpAsmClient singleton. Likely WRONG VA. Probable correct = 0x630e8 (= same as 5.50 + 6.02). TBD verify 6.50 byte-exact. Currently safe because B2 anchor=0 skips patch. */
      0UL, /* B2 anchor TBD — B2 SKIPPED first ship */
      0x150UL, /* libSceNpTrophy2 sceNpTrophy2CreateContext (★ stable) */
      0x18080UL, /* libSceNpTrophy2 DAT_01018080 (★ stable) */
      0, 0, 0, 0, 0, 0, /* B8-B18 disabled */
      0, 0, /* B20+B21 TBD (IsDeprecatedVersion exists, check runtime — probable required since 6.02 hérite) */
      0UL /* B22 NEW r19.55 — RecoveryRequired reader bypass (4.x only) */
    },
    /* 6.02 — RE 2026-05-20 byte-exact verification.
     * Pre-Cronos hybrid era entre 5.50 et 6.50. Sony build dir J02302929
     * (= between 5.50 J02159366 and 6.50 J02466812).
     *
     * Cross-binary diffs vs 6.50:
     * - B1 ×4 @ IDENTICAL VAs (0x02b5b398/3a4/af8/b04) byte-exact verified
     * prologue `41 41 41 41 30 30 30 30 30` AAAA00000
     * - B5_LNC same FUN_014d3ad0 (= getSceSysDirPath lnc_manager.cpp:0xa7a)
     * but JZ site shifted -0x70 INSIDE: 6.50 @ 0x014d3c5c → 6.02 @ 0x014d3bec
     * LONG JZ `0f 84 86 00 00 00` byte-exact + attr offset +0x104 STABLE
     * - libSceNpManager: NpAsmClient singleton @ 0x630e8 byte-exact verified
     * via FUN_0102d410 ctor `DAT_010630e8 = operator_new(200)` + vtable +
     * SceNpAsmClientLock mutex init. NOT 0x5d1c0 (= PTR___stack_chk_guard
     * stack canary, used by `-fstack-protector` epilogue checks).
     * - libSceNpManager anchor sceNpIntGetNpTitleIdSecret @ 0x14f80 byte-exact
     * (= tail-thunk wrapper calling sceNpAsmClientGetNpTitleId @ 0x29380)
     * - libSceNpTrophy2 ABI 100% STABLE byte-exact vs 4.03→12.70:
     * B6 CreateContext @ 0x150 prologue `55 48 89 e5 41 57 41 56 41 55 41 54
     * 53 48 83 ec` + DAT_01018080 NULL.bss
     *
     * 🐛 CRITICAL: 6.02 HAS THE SAME SONY 4.03 LAUNCH FW BUG:
     * - CreateUserDataFile (FUN_01bbc920) sets version=0x10000
     * - IsDeprecatedVersion stub @ FUN_01bbcf30 → core FUN_01bbf100:
     * `return *(int *)(param_1 + 0x68) == 0x10000;`
     * storage_user_data.cpp:0x1e8 / data_file/user_data_file.cpp:0x2df
     * → ALWAYS TRUE on fresh install
     * - UpdateSummaryFile (FUN_01bbd250) → if deprecated → DELETE trpsummary
     * - trpbroken.dat cascade present @ string 0x0293c6aa (= mirror 4.03)
     *
     * → B20+B21+B22 trio REQUIRED on 6.02 (= same r19.55 fix as 4.03):
     * - B20 @ 0x01bbcf30 stub → patch `31 C0 C3` (xor eax,eax; ret)
     * - B21 @ 0x01bc01a0 inner SetRecoveryRequired in data_file/user_data_file.cpp
     * NOTE: B21 wrapper FUN_01aa0150 style is REMOVED on 6.02. Sony inlined
     * the bit-set logic into 2 callers (CreateUserDataFile + UpdateTitleEntry)
     * that conditionally call the inner setter FUN_01bc01a0. Patch prologue
     * `31 C0 C3` (xor eax,eax; ret) → returns 0 success without write to
     * bit @ offset 0x6c.
     * - B22 @ 0x01bbdd40 GetRecoveryRequired signature `(long, void*, byte*)`
     * → patch `31 C0 88 02 C3` (xor eax,eax; mov [rdx],al; ret) byte-exact
     * match (RDX = param_3 = byte ptr out)
     *
     * Cronos infrastructure compiled but DORMANT runtime:
     * - np_bind_dat2_file.cpp string @ 0x028bf974 (compiled file loader)
     * - AppSubcontainerPrepareNpForCronos strings @ 0x0289da3d / 0x02930fce
     * - sceKernelIsCronos check @ 0x028a1f51 (returns 0 on pre-Cronos retail)
     *
     * KISS minimal set: B1 + B5_LNC + B6 + B2 (DAT + anchor) + B20+B21+B22.
     * B3 DISABLED (pre-Cronos file loader sabotage like 4.03/5.50/6.50).
     * B4 disabled first ship.
     * B13/B14/B15 NOT needed (permissive User checks like 6.50/9.40, NOT Cronos
     * strict). 6.02 = NOT in is_cronos branch (= sentinel return 2 pre-Cronos). */
    { "6.02",
      { 0x02b5b398UL, 0x02b5b3a4UL, 0x02b5baf8UL, 0x02b5bb04UL },
      { 0UL, 0UL }, /* B3 DISABLED — pre-Cronos hybrid file loader */
      0UL, 0x014d3becUL, /* B4 disabled first ship; B5_LNC LONG JZ @ 0x014d3bec (attr +0x104) */
      0x630e8UL, /* libSceNpManager NpAsmClient DAT_010630e8 byte-exact (NOT 0x5d1c0 = stack canary) */
      0x14f80UL, /* libSceNpManager sceNpIntGetNpTitleIdSecret @ 0x01014f80 byte-exact */
      0x150UL, /* libSceNpTrophy2 CreateContext (★ STABLE byte-exact 4.03→12.70) */
      0x18080UL, /* libSceNpTrophy2 DAT_01018080 (★ STABLE byte-exact) */
      0UL, 0UL, 0UL,
      0UL, 0UL, 0UL, /* B8-B18 disabled — pre-Cronos era */
      0x01bbcf30UL, /* B20 — IsDeprecatedVersion stub (Sony 4.03-like bug ACTIVE on 6.02) */
      0x01bc01a0UL, /* B21 — inner SetRecoveryRequired data_file/user_data_file.cpp (wrapper removed) */
      0x01bbdd40UL /* B22 — GetRecoveryRequired with byte ptr out (= 4.03 pattern) */
    },
    /* 7.20 — Sony build dir J02614549 (between 6.50 J02466812 and 7.61).
     * Pre-Cronos HYBRID era (like 5.50/6.50/8.00/9.00/9.60): Cronos infrastructure
     * compiled (AppSubcontainerPrepareNpForCronos + np_bind_dat2_file.cpp strings
     * present) but runtime sceKernelIsCronos returns 0 → file_loader path active.
     * B3 candidate FUN_01a0fda0 verified = network serializer (sceNetHtonl/StreamWriter),
     * NOT crypto stub. B3 disabled-by-design (sentinel return 2, pre-Cronos branch).
     * libSceNpManager + libSceNpTrophy2 byte-identical to 7.61 (B2 DAT 0x63118 +
     * anchor 0x14fe0, B6 0x150 + 0x18080). B5_LNC LONG JZ pre-Cronos +0x104 attr
     * offset (TEST `f6 86 04 01 00 00 06 0f 84`). */
    { "7.20",
      { 0x02d273c8UL, 0x02d273d4UL, 0x02d27b28UL, 0x02d27b34UL },
      { 0UL, 0UL }, /* B3 DISABLED — hybrid era, file loader sabotage (sentinel return 2 pre-Cronos branch) */
      0UL, 0x01579676UL, /* B4 disabled first ship; B5_LNC LONG JZ position 0x01579676 (TEST [RSI+0x104] + LONG JZ 6 bytes — patch NOPs all 6) */
      0x63118UL, /* libSceNpManager DAT_01063118 byte-exact == 7.61 (NULL.bss confirmed) */
      0x14fe0UL, /* libSceNpManager sceNpIntGetNpTitleIdSecret @ 0x01014fe0 byte-exact == 7.61 (16-byte tail-thunk) */
      0x150UL, /* libSceNpTrophy2 sceNpTrophy2CreateContext (★ stable cross-fw) */
      0x18080UL, /* libSceNpTrophy2 DAT_01018080 client state (★ stable cross-fw) */
      0UL, /* B8 DISABLED — pre-Cronos era */
      0UL, /* B9 DISABLED */
      0UL, /* B10 DISABLED */
      0UL, /* B5_auth DISABLED */
      0UL, /* B12 DISABLED */
      0UL, /* B18 DISABLED */
      0UL, /* B20 NOT needed on 7.20 (Sony fixed in earlier pre-Cronos) */
      0UL, /* B21 NOT needed on 7.20 */
      0UL /* B22 NOT needed on 7.20 */
    },
    /* 7.60 — Sony build dir (between 7.20 J02614549 and 7.61). Pre-Cronos HYBRID
     * era — AppSubcontainerPrepareNpForCronos string present in SceShellCore +
     * B3 candidate FUN_01a0fdc0 is a file loader (StreamCtx* signature, 514-byte
     * body), NOT a crypto stub. B3 disabled-by-design (sentinel return 2 →
     * pre-Cronos branch B7+B2+B6 runs naturally).
     *
     * BYTE-EXACT IDENTICAL to 7.61 except B3 status:
     * - B1 ×4 strings byte-identical (0x02d373e8/3f4/b48/b54)
     * - B5_LNC byte-identical (0x0157e166 short JZ + attr offset +0x104)
     * - libSceNpManager DAT 0x63118 + anchor 0x14fe0 byte-identical
     * - libSceNpTrophy2 0x150 + 0x18080 stable cross-fw
     *
     * Diff vs 7.61: Sony refactored B3 between 7.60→7.61 (file loader →
     * crypto stub). Verified byte-exact. */
    { "7.60",
      { 0x02d373e8UL, 0x02d373f4UL, 0x02d37b48UL, 0x02d37b54UL },
      { 0UL, 0UL }, /* B3 DISABLED — hybrid file loader (sentinel return 2 → pre-Cronos branch) */
      0x016bc380UL, 0x0157e166UL, /* r19.70 B4 wrapper RE'd via 7.40 cross-ref (lib byte-stable 7.40-7.61); B5_LNC short JZ byte-identical 7.61 (attr offset +0x104) */
      0x63118UL, /* libSceNpManager DAT_01063118 byte-identical 7.61 (NULL.bss) */
      0x14fe0UL, /* libSceNpManager sceNpIntGetNpTitleIdSecret @ 0x01014fe0 byte-identical 7.61 */
      0x150UL, /* libSceNpTrophy2 sceNpTrophy2CreateContext stable cross-fw */
      0x18080UL, /* libSceNpTrophy2 DAT_01018080 client state stable cross-fw */
      0UL, /* B8 DISABLED — pre-Cronos era */
      0UL, /* B9 DISABLED */
      0UL, /* B10 DISABLED */
      0UL, /* B5_auth DISABLED */
      0UL, /* B12 DISABLED */
      0UL, /* B18 DISABLED */
      0UL, /* B20 NOT needed on 7.60 */
      0UL, /* B21 NOT needed on 7.60 */
      0UL /* B22 NOT needed on 7.60 */
    },
    /* 7.20 — r19.70 RE 2026-05-23 byte-exact.
     * Pre-Cronos HYBRID pattern (= np_bind_dat2_file.cpp present @ 0x02b7e4db,
     * Sony build dir J02614549). Lib layout:
     * - B1 ×4 AAAA strings: 0x02d273c8/3d4/b28/b34 (shift -0xC020 vs 7.40)
     * - B5_LNC site: 0x01579676 (shift -0x4af0 vs 7.40, short JZ 74 1A, attr +0x104)
     * - B4 wrapper: DISABLED first ship (= 0x016bc380 on 7.40-7.61 IS DIFFERENT
     * function on 7.20, B4 elsewhere — TBD RE)
     * - libSceNpManager: DAT 0x63118 + anchor 0x14fe0 (IDENTICAL 7.40+, byte-stable family)
     * - libSceNpTrophy2: 0x150 + 0x18080 (stable cross-fw)
     * B3 disabled (= hybrid pre-Cronos sentinel like 9.60). */
    { "7.20",
      { 0x02d273c8UL, 0x02d273d4UL, 0x02d27b28UL, 0x02d27b34UL },
      { 0UL, 0UL }, /* B3 DISABLED — pre-Cronos hybrid */
      0UL, 0x01579676UL, /* B4 disabled first ship; B5_LNC short JZ */
      0x63118UL, /* libSceNpManager DAT_01063118 (= byte-stable 7.x family) */
      0x14fe0UL, /* libSceNpManager sceNpIntGetNpTitleIdSecret @ 0x01014fe0 (= byte-stable) */
      0x150UL, /* libSceNpTrophy2 CreateContext (stable cross-fw) */
      0x18080UL, /* libSceNpTrophy2 DAT_01018080 (stable cross-fw) */
      0, 0, 0,
      0, 0, 0,
      0, 0, 0UL
    },
    /* 7.40 — r19.69 RE 2026-05-23 byte-exact.
     * Pre-Cronos HYBRID pattern (= np_bind_dat2_file.cpp present @ 0x02b58321,
     * Cronos infrastructure compiled but inert runtime). Lib layout:
     * - B1 ×4 AAAA strings: shift -0x4000 vs 7.61 (SceShellCore.rodata reorg)
     * - B5_LNC site: 0x0157e166 (IDENTICAL 7.61, short JZ 74 1A, attr +0x104)
     * - B4 wrapper: 0x016bc380 (IDENTICAL 7.61)
     * - libSceNpManager: DAT 0x63118 + anchor 0x14fe0 (IDENTICAL 7.61, byte-stable)
     * - libSceNpTrophy2: 0x150 + 0x18080 (stable cross-fw)
     * B3 disabled (= hybrid pre-Cronos sentinel like 9.60). */
    { "7.40",
      { 0x02d333e8UL, 0x02d333f4UL, 0x02d33b48UL, 0x02d33b54UL },
      { 0UL, 0UL }, /* B3 DISABLED — pre-Cronos hybrid */
      0x016bc380UL, 0x0157e166UL,
      0x63118UL, /* libSceNpManager DAT_01063118 (= identical 7.61) */
      0x14fe0UL, /* libSceNpManager sceNpIntGetNpTitleIdSecret @ 0x01014fe0 (= identical 7.61) */
      0x150UL, /* libSceNpTrophy2 CreateContext (stable cross-fw) */
      0x18080UL, /* libSceNpTrophy2 DAT_01018080 (stable cross-fw) */
      0, /* B8 NOT needed on 7.40 (pre-Cronos hybrid, path B default) */
      0, /* B9 NOT needed */
      0, /* B10 NOT needed */
      0, /* B5_auth disabled */
      0, /* B12 NOT needed */
      0, /* B18 NOT needed */
      0, /* B20 NOT needed (Sony fixed IsDeprecatedVersion 5.50+) */
      0, /* B21 NOT needed */
      0UL /* B22 NOT needed (4.x only) */
    },
    /* 7.61 — RE 2026-05-13 (byte-exact verified). */
    { "7.61",
      { 0x02d373e8UL, 0x02d373f4UL, 0x02d37b48UL, 0x02d37b54UL },
      { 0x01a0fdc0UL, 0x01a0f5e0UL },
      0x016bc380UL, 0x0157e166UL,
      0x63118UL, /* libSceNpManager DAT_01063118 (shifted -0x10 vs 9.40) */
      0x14fe0UL, /* libSceNpManager anchor (shifted -0x330 vs 9.40) */
      0x150UL, /* libSceNpTrophy2 CreateContext (identical 9.40) */
      0x18080UL, /* libSceNpTrophy2 DAT_01018080 (identical 9.40) */
      0, /* B8 NOT needed on 7.61 (validated runtime, byte = 1, path B default) */
      0, /* B9 NOT needed on 7.61 (vtable byte = 1) */
      0, /* B10 NOT needed on 7.61 (validated runtime, path B works) */
      0, /* B5 disabled on 7.61 (RegisterContext works) */
      0, /* B12 NOT needed on 7.61 (Path A produces valid commId) */
      0, /* B18 NOT needed on 7.61 (state byte correctly 0) */
      0, /* B20 NOT needed on 7.61 (Sony fixed IsDeprecatedVersion) */
      0, /* B21 NOT needed on 7.61 */
      0UL /* B22 NEW r19.55 — RecoveryRequired reader bypass (4.x only) */
    },
    /* 10.01 — KISS minimaliste (r19.10 revert) — mirror 9.40/7.61 pattern.
     * Earlier r19.5-r19.9 stacked B8+B9+B10+B5_auth nuclear patches based on
     * misunderstanding that Path B was the trophy register path. 
     * RE 2026-05-14 (~75 funcs decompiled) revealed:
     * - Real trophy install uses Path A worker (FUN_01d6f7b0) → SetupBindInfo
     * → LoadNpBindDatFile → reads npbind.dat from filesystem
     * - On 10.01 Cronos, daemon reads from /system_data/game/temp/<TID>/npbind.dat
     * (NEW PATH RE'd via FUN_01a96940) — old /system_data/priv/appmeta/ ignored
     * - The "Path B / IpcJob" stack (now patched) is for ULMS register (= PSN sync)
     * which is IRRELEVANT for offline install (= the actual use case)
     *
     * Fix r19.10 = B7 ADDITIONAL copy to /system_data/game/temp/<TID>/ done in
     * phu_trophy_setup_appmeta unconditionally. Same 5 patches as 9.40/7.61.
     *
     * libSceNpManager: DAT identique 9.40, anchor shifted -0x2D0 vs 9.40.
     * libSceNpTrophy2: zero drift vs 9.40+7.61 (structure très stable).
     * SceShellCore B4 wrapper FUN_01736d40: signature (uint, char*) = rsi=out,
     * 10-byte prologue couvre exactement notre patch payload. */
    { "10.01",
      { 0x02e8b4a8UL, 0x02e8b4b4UL, 0x02e8bc08UL, 0x02e8bc14UL },
      /* r19.26 ROOT CAUSE FIX — DISABLE B3 ON 10.01.
       *
       * RE 2026-05-14 evening: FUN_01aede40 on 10.01 is NOT a crypto
       * bypass like FUN_01a9dfe0 was on 9.40. It is a FILE PATH BUILDER + LOADER:
       * 1. FUN_01aee7b0 builds empty LocalFilePath
       * 2. sceKernelIsCronos checked (= 1 on PS5 10.01)
       * 3. Cronos+param_4!=0 branch → FUN_01aeeed0 builds path
       * "/system_data/game/temp/<TID>/<suffix>" where suffix = "trophy2/npbind.dat"
       * (passed by Path A caller FUN_01d1c650 as 0x2d5f0a0 string ptr)
       * 4. FUN_01aee5a0(filepath,...) opens file + parses → populates *param_6
       *
       * The B3 patch `xor eax,eax; ret` SHORTCIRCUITS this:
       * - Returns 0 (success) ✓
       * - BUT param_6 stays NULL (never written) ✗
       * - Caller FUN_01d1c650 sees `local_48 == 0` → returns 0x8055390c
       *
       * That's THE FIRST error code seen on 10.01 (r19.5). All subsequent
       * patches B8/B9/B10/B11/B12/B17/B18 were band-aids on the cascade:
       * - B8 forced Path B (because Path A returned 0x8055390c)
       * - B9 fixed Path B vtable check (because forced into broken Path B)
       * - B10 nuked Path B entry (because Path B was also broken)
       * - B11 initialized DAT_02f52010 (because Path B needs it)
       * - B12 NOP'd commId JZ (because cascade error 0x8055391a)
       * - B17 patched 4× MOV 0x8055391e (because cascade error 0x8055391e)
       * - B18 forced first-time path (because cascade error still 0x8055391e)
       *
       * REAL FIX: DON'T patch FUN_01aede40 on 10.01. Let it do its file loading.
       * Files are already in place at /system_data/game/temp/<TID>/trophy2/ via
       * the B7 r19.10 copy. B1 (AAAA strings) makes daemon accept arbitrary
       * commId so file parsing succeeds. Trophy register should work naturally.
       *
       * Keep B13/B14/B15/B16 on (User state bypass for offact accounts).
       * Drop B3/B8/B9/B10/B11/B12/B17/B18 (all caused by B3 sabotage).
       * Drop B5_auth (DebugUnlock not needed if RegisterContext works). */
      { 0UL, 0UL }, /* B3 DISABLED — was sabotaging file loader */
      0x01736d40UL, 0x015d8511UL, /* B4 audit-fix wrapper; B5_LNC byte 74 1A verified */
      0x63128UL, /* libSceNpManager DAT (identical 9.40) */
      0x15040UL, /* libSceNpManager anchor (shifted -0x2D0 vs 9.40) */
      0x150UL, /* libSceNpTrophy2 CreateContext (identical) */
      0x18080UL, /* libSceNpTrophy2 DAT_01018080 (identical) */
      0UL, /* B8 DISABLED — was cascade fix for B3 sabotage */
      0UL, /* B9 DISABLED — was cascade fix for forced Path B */
      0UL, /* B10 DISABLED — was cascade fix for broken Path B */
      0UL, /* B5_auth DISABLED — DebugUnlock not needed */
      0UL, /* B12 DISABLED — was cascade fix for 0x8055391a */
      0UL, /* B18 DISABLED — was cascade fix for 0x8055391e */
      0UL, /* B20 NOT needed on 10.01 (Cronos has different version handling) */
      0UL, /* B21 NOT needed on 10.01 */
      0UL /* B22 NEW r19.55 — RecoveryRequired reader bypass (4.x only) */
    },
    /* 10.00 — RE 2026-05-20 byte-exact (parallel
     * cross-binary verification). Cronos era launch fw = quasi-clone 10.01.
     *
     * Sony build dir: J03357167 (vs 10.01 différent).
     *
     * Cross-binary diff matrix vs 10.01:
     * - SceShellCore:
     * - B1 ×4 @ 0x02e8b4a8/4b4/c08/c14 byte-exact STABLE
     * - B4 wrapper @ 0x01736d40 byte-exact STABLE (prologue 10-byte preserved)
     * - B5_LNC JZ pos @ 0x015d8511 STABLE VA, mais attr offset shifted
     * +0x30 (`[RSI+0xd4]` 10.01 → `[RSI+0x104]` 10.00). NOP patch
     * `74 1A → 90 90` INSENSIBLE à l'offset attr → fonctionne identique.
     * - B3 file loader FUN_01aede40 byte-exact STABLE → MUST stay DISABLED.
     * - B17 cluster shift -0x300 (FUN_01d504d0 → FUN_01d501d0) mais
     * gated 10.01-only = NOT applied 10.00 first ship (mirror KISS lesson).
     * - libSceNpManager: 100% byte-identique (B2 DAT 0x63128 + anchor 0x15040
     * + struct fields +0x14/24/a4/a5/a6/b8/bc all STABLE).
     * - libSceNpTrophy2: 100% byte-identique (B6 0x150 + 0x18080).
     *
     * KISS Cronos pattern minimal (= mirror 10.01 r19.26):
     * B1 + B4 + B5_LNC + B2 (NpManager) + B6 (Trophy2) actifs
     * B3 DISABLED (Cronos file loader sabotage)
     * B13/B14/B15 actifs via gates étendues (User state strict Cronos).
     *
     * 10.00 = launch fw Cronos era — struct lnc app_info encore en transition
     * pre-Cronos (+0x104 like 5.50/6.50) vers Cronos pur (+0xd4 sur 10.01+).
     * Sony a fini le refactor entre 10.00 → 10.01. */
    { "10.00",
      { 0x02e8b4a8UL, 0x02e8b4b4UL, 0x02e8bc08UL, 0x02e8bc14UL },
      { 0UL, 0UL }, /* B3 DISABLED — Cronos file loader sabotage (FUN_01aede40) */
      0x01736d40UL, 0x015d8511UL, /* B4 wrapper byte-exact == 10.01; B5_LNC JZ pos byte-exact == 10.01 (attr offset diff 0xd4→0x104 = NOP-insensitive) */
      0x63128UL, /* libSceNpManager DAT_01063128 byte-exact == 10.01 (struct layout STABLE) */
      0x15040UL, /* libSceNpManager sceNpIntGetNpTitleIdSecret @ 0x01015040 byte-exact == 10.01 (16-byte tail-thunk identical) */
      0x150UL, /* libSceNpTrophy2 sceNpTrophy2CreateContext (★ stable cross-fw, byte-exact verified) */
      0x18080UL, /* libSceNpTrophy2 DAT_01018080 client state (★ stable cross-fw, NULL.bss confirmed) */
      0UL, /* B8 DISABLED — Cronos era, no cascade fix needed */
      0UL, /* B9 DISABLED */
      0UL, /* B10 DISABLED */
      0UL, /* B5_auth DISABLED */
      0UL, /* B12 DISABLED */
      0UL, /* B18 DISABLED — beta runtime will reveal if 0x8055391e cascade fires */
      0UL, /* B20 NOT needed on 10.00 (Cronos has different version handling) */
      0UL, /* B21 NOT needed on 10.00 */
      0UL /* B22 NOT needed on 10.00 (Cronos era, no RecoveryRequired bug) */
    },
    /* 10.20 — Sony build dir J03410042. Cronos era quasi-clone 10.00/10.01 with
     * +0x8000 shift on SceShellCore.rodata. B5_LNC attr offset pre-Cronos style
     * (+0x104) like 10.00 — NOP patch insensitive to offset. libSceNpManager and
     * libSceNpTrophy2 byte-identical to 10.01 (DAT 0x63128, anchor 0x15040, B6
     * 0x150 + 0x18080). B4 wrapper not RE'd first ship (disabled-by-design like
     * 12.00 first ship — beta runtime will reveal if needed). */
    { "10.20",
      { 0x02e934a8UL, 0x02e934b4UL, 0x02e93c08UL, 0x02e93c14UL },
      { 0UL, 0UL }, /* B3 DISABLED — Cronos file loader sabotage */
      0UL, 0x015d8511UL, /* B4 disabled first ship; B5_LNC byte-exact == 10.00/10.01 (attr offset +0x104 pre-Cronos style, NOP-insensitive) */
      0x63128UL, /* libSceNpManager DAT_01063128 byte-exact == 10.00/10.01 (NULL.bss confirmed) */
      0x15040UL, /* libSceNpManager sceNpIntGetNpTitleIdSecret @ 0x01015040 byte-exact == 10.00/10.01 (16-byte tail-thunk) */
      0x150UL, /* libSceNpTrophy2 sceNpTrophy2CreateContext (★ stable cross-fw) */
      0x18080UL, /* libSceNpTrophy2 DAT_01018080 client state (★ stable cross-fw) */
      0UL, /* B8 DISABLED — Cronos era */
      0UL, /* B9 DISABLED */
      0UL, /* B10 DISABLED */
      0UL, /* B5_auth DISABLED */
      0UL, /* B12 DISABLED */
      0UL, /* B18 DISABLED */
      0UL, /* B20 NOT needed on 10.20 (Cronos) */
      0UL, /* B21 NOT needed on 10.20 */
      0UL /* B22 NOT needed on 10.20 */
    },
    /* 12.00 — RE 2026-05-17.
     * Cronos era (post-10.01) — same architectural pattern as 10.01:
     * - B3 file loaders → DISABLED-by-design (Cronos auto-prepare via
     * AppSubcontainerPrepareNpForCronos handles /system_data/game/temp/<TID>/)
     * - B17 0x8055391e bypass FUN_01d504d0 RE'd (5× MOV verified inside body)
     * - B4 inventory wrapper FUN_017e0b70 (3-arg signature + xref 0x80a40005
     * @ 0x017e0bc8 matches 9.40 pattern)
     * - B5_LNC short JZ `74 60` verified byte-exact @ 0x016557aa
     * - B6 trophy2 offsets stable (0x150 + 0x18080 cross-fw)
     *
     * KISS minimal set (mirror r19.26 lesson): skip B8-B16/B18 unless beta
     * runtime reveals specific Cronos checks that fire. Most "Cronos extras"
     * were band-aids on B3 sabotage = irrelevant when B3 is correctly disabled.
     *
     * Canadian beta diag (PHUdiag.txt 2026-05-16) confirms overlay BOOT +
     * INJECT + sampler OK on fw 12.00. Only "B1 fw not supported" blocked
     * trophy install — this row fixes that gate.
     *
     * libSceNpManager 12.00: NpAsmClient DAT @ 0x63168 (+0x40 vs 9.40),
     * anchor sceNpIntGetNpTitleIdSecret @ 0x16640.
     * SceShellCore B4 wrapper FUN_017e0b70: signature (char*, uint, undefined8*)
     * matches 9.40's FUN_017266c0 pattern, 10-byte prologue. */
    { "12.00",
      { 0x02f545a8UL, 0x02f545b4UL, 0x02f54d08UL, 0x02f54d14UL },
      { 0UL, 0UL }, /* B3 DISABLED — Cronos file loader (sentinel returns 0 like 10.01) */
      /* B4 DISABLED on 12.00 first-ship — FUN_017e0b70 found via 0x80a40005 xref
       * has non-standard prologue (b8 01 00 a4 80 = mov eax, 0x80a40001 = dispatcher,
       * not wrapper). Skipping B4 = let Cronos auto-prepare handle inventory check.
       * If beta runtime reveals trophy install fails on inventory gate, will re-RE
       * proper wrapper. B5_LNC verified byte-exact. */
      0UL, 0x016557aaUL, /* B4 disabled (TBD if needed); B5_LNC short JZ 74 60 verified */
      0x63168UL, /* libSceNpManager DAT_01063168 (+0x40 vs 9.40) */
      0x16640UL, /* libSceNpManager sceNpIntGetNpTitleIdSecret @ 0x01016640 */
      0x150UL, /* libSceNpTrophy2 sceNpTrophy2CreateContext (★ stable cross-fw) */
      0x18080UL, /* libSceNpTrophy2 DAT_01018080 client state (★ stable cross-fw) */
      0UL, /* B8 DISABLED — Cronos era, B3 sabotage cascade fix not needed */
      0UL, /* B9 DISABLED */
      0UL, /* B10 DISABLED */
      0UL, /* B5_auth DISABLED */
      0UL, /* B12 DISABLED */
      0UL, /* B18 DISABLED — beta runtime will reveal if 0x8055391e cascade fires */
      0UL, /* B20 NOT needed on 12.00 (Cronos has different version handling) */
      0UL, /* B21 NOT needed on 12.00 */
      0UL /* B22 NEW r19.55 — RecoveryRequired reader bypass (4.x only) */
    },
    /* 12.70 PS5 Pro — RE deep verification 2026-05-19 (Sony build dir J03828161).
     * Full Cronos era refresh of 12.00 — minor refresh, architecture INCHANGÉE:
     * - libSceNpManager.sprx: layout struct IDENTIQUE à 12.00 (NpAsmClient DAT 0x63168 +
     * anchor 0x16640 + struct fields +0x14/+0x24/+0xa4/+0xa5/+0xa6/+0xb8/+0xbc preserved
     * byte-exact). B2 inject code works UNCHANGED.
     * - libSceNpTrophy2.sprx: SHRUNK -25KB (99KB vs 9.40 124KB) — Sony stripped legacy
     * callback handlers, MAIS ABI offsets 0x150 + 0x18080 PRESERVED byte-stable.
     * - SceShellCore: minor function shifts (+0x8000 B1.rodata, +0x1250 B5_LNC.text).
     * - Cronos infrastructure FULLY ACTIVE: AppSubcontainerPrepareNpForCronos called
     * from FUN_017ac4b0 (AppPromoter main flow), sceKernelIsCronos consulted by 7+
     * callsites, ULMS infrastructure (np_trophy2_ulms_manager.cpp, SceNpUlmsServer
     * strings) present.
     * - 2 new error codes: 0x80553995 (= renamed 0x8055390c BIND_INFO_NOT_FOUND) +
     * 0x805539bd (= renamed 0x8055169A CTX_MAP_MISS). Semantic identical, just Sony
     * namespace cleanup. PHU error decoder may need update if explicit log handling.
     *
     * Byte-exact verified:
     * - B1 ×4 strings @ 0x02f5c5a8/5b4/d08/d14 (`41 41 41 41 30 30 30 30 30`)
     * - B5_LNC @ 0x016569fa, pre-bytes `f6 86 d4 00 00 00 06 74 60` (TEST [RSI+0xd4],0x6
     * + SHORT JZ +0x60), same attr offset +0xd4 as 10.01/11.20/11.60/12.00 Cronos
     *
     * KISS Cronos pattern (= mirror 12.00): B1 + B2 + B5_LNC + B6 actifs, B3+B4 disabled
     * (Sony auto-prepare handles). All B8-B21 = 0 (Cronos era doesn't need cascade fix). */
    /* 12.40 — r19.70 RE 2026-05-23 byte-exact.
     * Cronos era. B1 strings IDENTICAL 12.00. Lib byte-stable 12.00→12.40 (DAT/anchor same). */
    { "12.40",
      { 0x02f545a8UL, 0x02f545b4UL, 0x02f54d08UL, 0x02f54d14UL },
      { 0UL, 0UL }, /* B3 DISABLED — Cronos auto-prepare */
      0UL, 0x016557aaUL, /* B4 disabled first ship; B5_LNC short JZ 74 60 (Cronos attr +0xd4) */
      0x63168UL, /* libSceNpManager DAT_01063168 (= IDENTICAL 12.00) */
      0x16640UL, /* libSceNpManager sceNpIntGetNpTitleIdSecret @ 0x01016640 (= IDENTICAL 12.00) */
      0x150UL, /* libSceNpTrophy2 CreateContext (stable cross-fw) */
      0x18080UL, /* libSceNpTrophy2 DAT_01018080 (stable cross-fw) */
      0UL, 0UL, 0UL,
      0UL, 0UL, 0UL,
      0UL, 0UL, 0UL
    },
    { "12.70",
      { 0x02f5c5a8UL, 0x02f5c5b4UL, 0x02f5cd08UL, 0x02f5cd14UL },
      { 0UL, 0UL }, /* B3 DISABLED — Cronos era */
      0UL, 0x016569faUL, /* B4 disabled first ship; B5_LNC short JZ 74 60 byte-exact */
      0x63168UL, /* libSceNpManager DAT_01063168 (= IDENTICAL à 12.00, struct layout preserved) */
      0x16640UL, /* libSceNpManager sceNpIntGetNpTitleIdSecret @ 0x01016640 (= IDENTICAL à 12.00) */
      0x150UL, /* libSceNpTrophy2 sceNpTrophy2CreateContext (★ stable cross-fw, verified 4.03→12.70) */
      0x18080UL, /* libSceNpTrophy2 DAT_01018080 client state (★ stable, ABI preserved despite -25KB lib shrink) */
      0UL, /* B8 DISABLED — Cronos */
      0UL, /* B9 DISABLED */
      0UL, /* B10 DISABLED */
      0UL, /* B5_auth DISABLED */
      0UL, /* B12 DISABLED */
      0UL, /* B18 DISABLED */
      0UL, /* B20 NOT needed (Cronos different version handling) */
      0UL, /* B21 NOT needed */
      0UL /* B22 NEW r19.55 — RecoveryRequired reader bypass (4.x only) */
    },
    /* 11.60 — RE 2026-05-17.
     * Cronos era (post-10.01) — same architectural pattern as 10.01 + 12.00:
     * - B3 file loaders → DISABLED-by-design (Cronos auto-prepare via
     * AppSubcontainerPrepareNpForCronos handles /system_data/game/temp/<TID>/)
     * - np_bind_dat2_file.cpp present → confirms Cronos era
     * - AppSubcontainerPrepareNpForCronos string @ 0x02d20e28 → confirmed
     * - B17 0x8055391e cluster RE'd FUN_01d2a540 (5 MOV at 0x01d2a6da/e2/80a/816/82c)
     * - B5_LNC short JZ `74 60` byte-exact @ 0x0164186a (FUN_01641660
     * getSceSysDirPath lnc_manager.cpp:0xa3d, attr & 0x6 == 0 → 0x8094000f)
     * - B6 trophy2 offsets stable (0x150 + 0x18080 cross-fw, validated)
     *
     * KISS minimal set (mirror r19.26/12.00 lesson): skip B4/B8-B18 first ship.
     * Beta runtime feedback will reveal if any specific Cronos check fires.
     *
     * libSceNpManager 11.60: NpAsmClient DAT @ 0x5d1c0 (shift vs other fws)
     * - read via MOV RAX,[0x0105d1c0] then deref (= standard singleton pattern)
     * SceShellCore B4 wrapper candidate FUN_017c3170: signature (char*, *out)
     * 2 args (not 3 like 9.40's FUN_017266c0) → disabled first ship pour safety. */
    /* 11.20 — RE 2026-05-17.
     * Cronos era (post-10.01, pre-11.60). Same KISS minimal Cronos pattern as
     * 11.60/12.00. Diff vs 11.60: binary shifted -0x8000 (B1) / -0x9900 (B17).
     * libSceNpManager UNCHANGED vs 11.60 (B2 DAT @ 0x5d1c0 stable, FUN_01029880
     * identical disasm). Sony build dir: J03595639 (vs J03675035 on 11.60).
     *
     * B1 strings: 0x02f30458/464/bb8/bc4 (shifted -0x8000 vs 11.60)
     * B5_LNC: 0x01638e1a short JZ `74 60` (FUN_01638c10 getSceSysDirPath,
     * attr & 0x6 == 0 → 0x8094000f, byte-exact verified)
     * B17 cluster: FUN_01d20c30 body 0x01d20c30-0x01d20f26
     * 5× MOV 0x8055391e at 0x01d20dca/dd2/efa/f06/f1c
     * (gated 10.01-only in code, NOT applied on 11.20)
     * Cronos era confirmed: np_bind_dat2_file.cpp +
     * AppSubcontainerPrepareNpForCronos strings present */
    /* 11.00 — Sony build dir J03553996 (between 10.20 J03410042 and 11.20 J03595639).
     * Cronos era quasi-clone 10.20/11.20. KEY DIFF vs 10.20: libSceNpManager grew
     * (4 new IPC inline functions sceNpIpcRealloc/Free/GetNpMemAllocator inserted
     * before sceNpIntGetNpTitleIdSecret) → B2 anchor shifted +0x16e0 to 0x01016720.
     * B5_LNC: Cronos +0xd4 attr offset (NOT pre-Cronos +0x104 like 10.20/9.00) —
     * NOP-insensitive. B6 + B2 DAT stable. */
    { "11.00",
      { 0x02f2c458UL, 0x02f2c464UL, 0x02f2cbb8UL, 0x02f2cbc4UL },
      { 0UL, 0UL }, /* B3 DISABLED — Cronos file loader sabotage */
      0UL, 0x01638caaUL, /* B4 disabled first ship; B5_LNC JZ byte position 0x01638caa (TEST [RSI+0xd4] Cronos style + JZ short) */
      0x63128UL, /* libSceNpManager DAT_01063128 byte-exact stable (NULL.bss confirmed) */
      0x16720UL, /* libSceNpManager sceNpIntGetNpTitleIdSecret @ 0x01016720 — SHIFTED +0x16e0 vs 10.x (4 new IPC funcs inserted before) */
      0x150UL, /* libSceNpTrophy2 sceNpTrophy2CreateContext (★ stable cross-fw) */
      0x18080UL, /* libSceNpTrophy2 DAT_01018080 client state (★ stable cross-fw) */
      0UL, /* B8 DISABLED — Cronos era */
      0UL, /* B9 DISABLED */
      0UL, /* B10 DISABLED */
      0UL, /* B5_auth DISABLED */
      0UL, /* B12 DISABLED */
      0UL, /* B18 DISABLED */
      0UL, /* B20 NOT needed on 11.00 (Cronos) */
      0UL, /* B21 NOT needed on 11.00 */
      0UL /* B22 NOT needed on 11.00 */
    },
    { "11.20",
      { 0x02f30458UL, 0x02f30464UL, 0x02f30bb8UL, 0x02f30bc4UL },
      { 0, 0 }, /* B3 DISABLED — Cronos file loader (sentinel returns 0 like 10.01) */
      0UL, 0x01638e1aUL, /* B4 disabled first ship; B5_LNC short JZ 74 60 verified */
      0x5d1c0UL, /* libSceNpManager DAT_0105d1c0 (= SAME as 11.60, unchanged lib) */
      0UL, /* B2 anchor TBD */
      0x150UL, /* libSceNpTrophy2 sceNpTrophy2CreateContext (★ stable cross-fw) */
      0x18080UL, /* libSceNpTrophy2 DAT_01018080 client state (★ stable cross-fw) */
      0, 0, 0, 0, 0, 0, /* B8-B18 disabled (KISS Cronos pattern) */
      0, 0, /* B20+B21 NOT needed on 11.20 (Cronos version handling) */
      0UL /* B22 NEW r19.55 — RecoveryRequired reader bypass (4.x only) */
    },
    { "11.60",
      { 0x02f38458UL, 0x02f38464UL, 0x02f38bb8UL, 0x02f38bc4UL },
      { 0, 0 }, /* B3 DISABLED — Cronos file loader (sentinel returns 0 like 10.01) */
      /* B4 DISABLED on 11.60 first ship — FUN_017c3170 wrapper has 2-arg signature
       * differing from 9.40 standard 3-arg wrapper. Cronos auto-prepare should
       * handle inventory check. If beta runtime needs B4, re-RE proper wrapper. */
      0UL, 0x0164186aUL, /* B4 disabled; B5_LNC short JZ 74 60 verified */
      0x5d1c0UL, /* libSceNpManager DAT_0105d1c0 (singleton ptr) */
      0UL, /* B2 anchor TBD (= KISS skip first ship) */
      0x150UL, /* libSceNpTrophy2 sceNpTrophy2CreateContext (★ stable cross-fw) */
      0x18080UL, /* libSceNpTrophy2 DAT_01018080 client state (★ stable cross-fw) */
      0, /* B8 DISABLED — Cronos era */
      0, /* B9 DISABLED */
      0, /* B10 DISABLED */
      0, /* B5_auth DISABLED */
      0, /* B12 DISABLED */
      0, /* B18 DISABLED — beta runtime will reveal if needed */
      0, /* B20 NOT needed on 11.60 (Cronos version handling) */
      0, /* B21 NOT needed on 11.60 */
      0UL /* B22 NEW r19.55 — RecoveryRequired reader bypass (4.x only) */
    },
    { NULL, {0,0,0,0}, {0,0}, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};

/* Stateless lookup. Returns NULL if current fw is not in the table.
 * Caller MUST handle NULL (= unsupported fw → skip trophy install).
 * Cheap: strcmp loop over N=2 entries, no syscall, no allocation. */
static const phu_trophy_fw_offsets_t *get_fw_offsets(void) {
    const phu_fw_offsets_t *fw = phu_fw_offsets_current;
    if (!fw || !fw->fw_label) return NULL;
    for (size_t i = 0; g_trophy_fw_table[i].fw_label; i++) {
        if (strcmp(g_trophy_fw_table[i].fw_label, fw->fw_label) == 0) {
            return &g_trophy_fw_table[i];
        }
    }
    return NULL;
}

/* ============================================================================
 * Internal constants — SceShellCore.elf fw 9.40 string addresses
 * ----------------------------------------------------------------------------
 * RE'd VAs for the 4 "AAAA00000" string occurrences. The image base may
 * have been 0x01000000 (SCE convention) OR 0x00000000 (raw load). Probe
 * both candidates at runtime and pick the one that matches.
 *
 * NB r19.4: kept as 9.40 fallback / documentation. Patch functions now
 * lookup via get_fw_offsets for multi-fw support. LTO removes if unused.
 * ============================================================================ */
static constexpr uintptr_t AAAA_VAS[4] = {
    0x02e7f488UL, /* Trophy 2 main */
    0x02e7f494UL, /* Trophy 2 NetSync */
    0x02e7fbe8UL, /* Trophy 1 NetSync */
    0x02e7fbf4UL, /* Trophy 1 main */
};

/* Candidate image bases to probe — try the first that yields the
 * "AAAA00000" pattern at the expected slot[0] VA. */
static constexpr uintptr_t IMAGE_BASE_CANDIDATES[2] = {
    0x01000000UL, /* SCE convention (current bake) */
    0x00000000UL, /* raw file-offset load (ELF default for some ELFs) */
};

static constexpr const char AAAA_ORIGINAL[10] = "AAAA00000"; /* 9 chars + null */
static constexpr const char AAAA_PATCHED[10] = "ZZZZZZZZZ"; /* 9 chars + null */

/* ============================================================================
 * B3 — npbind.dat crypto bypass patches (fw 9.40 image base 0x01000000)
 * ----------------------------------------------------------------------------
 * Trophy 2 register flow IPMI cmd 0x90016 → SceShellCore handler FUN_01d7b310
 * → FUN_01d49630 (SetupBindInfo) → FUN_01a9e9f0 → FUN_01a9eff0
 * → FUN_01a9ed60 → FUN_01a9db60 (parse loop)
 * → FUN_01a9dfe0 (per-entry validator) ← PRIMARY GATE
 * → FUN_01a9fdc0 (NpCommSign builder)
 * → FUN_01a9fe50 (AES decrypt + read) ← BACKUP GATE
 *
 * The AES key is taken from the client's SceNpTitleSecret (128 bytes), but
 * the B2 cache injects a fake 0x5A×128 secret, so decryption produces
 * garbage and the function chain fails. Patching either function entry to
 * `xor eax, eax; ret` (= return 0 = success) bypasses the crypto gate.
 *
 * Patch BOTH for defense in depth:
 * - FUN_01a9dfe0 short-circuits the entire per-entry pipeline (entry obj
 * stays in fresh-init state from FUN_01a9e7c0)
 * - FUN_01a9fe50 short-circuits only the AES decrypt (entry obj is parsed
 * normally but signature bytes are garbage from failed decrypt)
 *
 * Both produce a "valid-looking" success that lets daemon proceed to
 * commit the trophy via FUN_01d2b3f0 → /user/trophy/conf/NPWR<id>_00/.
 * ============================================================================ */
static constexpr uintptr_t SHELLCORE_CRYPTO_BYPASS_VAS[2] = {
    0x01a9dfe0UL, /* FUN_01a9dfe0 entry — per-entry validator (primary) */
    0x01a9fe50UL, /* FUN_01a9fe50 entry — AES decrypt (backup) */
};
/* Patch payload: `xor eax, eax; ret` = 3 bytes. Replaces `push rbp; mov rbp, rsp;...`
 * function prologue. Caller doesn't care about callee internal stack — just
 * needs the call to return with eax = 0 = success. */
static constexpr uint8_t CRYPTO_BYPASS_PATCH[3] = { 0x33, 0xC0, 0xC3 };

/* r19.32 — forward declaration for rollback_record helper. Defined far below
 * with the rollback registry (line ~2000). Called by each do_*_patch function
 * just BEFORE the prw::proc_write to snapshot the SceShellCore pre-patch bytes
 * so phu_trophy_rollback_boot can restore vanilla state at game-vanish. */
static void rollback_record(pid_t shellcore_pid, uintptr_t va, size_t size);

/* ============================================================================
 * B4 — App inventory bypass (fw 9.40 image base 0x01000000)
 * ----------------------------------------------------------------------------
 * After B1+B2+B3, the daemon-side flow reaches FUN_01d2b3f0 (final commit
 * before /user/trophy/conf/NPWR*_00/ is created). That function gates on:
 *
 * FUN_017266c0(app, &out) -> queries SceShellCore's APP INVENTORY for the
 * running app's category. Inventory is a linked list at DAT_02ee7c08..
 * DAT_02ee7c10, stride 0x94, populated by Sony's INSTALLER at install
 * time (or pre-populated by OS for system apps like Astro's Playroom).
 * Raw DUMPS (copied via FTP, never went through pkg install) are NOT in
 * this list -> FUN_017177b0 returns NULL -> FUN_01744250 returns 0x80a40005
 * -> FUN_017266c0 returns < 0 -> FUN_01d2b3f0 SILENT SKIP, no error notif.
 *
 * This explains why Astro Bot dump trophy register produces zero klog
 * activity after B1+B2+B3 all succeed — the daemon reaches FUN_01d2b3f0
 * but exits silently because the app isn't in the inventory.
 *
 * Fix: patch FUN_017266c0 to force-write category = 2 to *(int*)(out+4)
 * and return 0. This bypasses the inventory check for ALL apps — the
 * gate now succeeds regardless of whether the app is installed legitimately.
 *
 * mov dword [rsi+4], 2; xor eax,eax; ret (10 bytes)
 * c7 46 04 02 00 00 00 31 c0 c3
 *
 * Trade-off: don't preserve the other fields FUN_017266c0 used to
 * populate (out[0], out[+8], out[+0xc] = byte/uint32/byte from the app's
 * metadata struct). FUN_01d2b3f0's caller (= this path) doesn't read those —
 * confirmed by code review of all uses of local_470 in FUN_01d2b3f0. */
static constexpr uintptr_t SHELLCORE_APP_INVENTORY_BYPASS_VA = 0x017266c0UL;
static constexpr uint8_t APP_INVENTORY_PATCH[10] = {
    0xc7, 0x46, 0x04, 0x02, 0x00, 0x00, 0x00, /* mov dword [rsi+4], 2 (force local_46c = 2 = "category installed") */
    0x31, 0xc0, /* xor eax, eax (return 0 = success) */
    0xc3 /* ret */
};
/* Expected original prologue bytes (sanity check before patching) */
static constexpr uint8_t APP_INVENTORY_ORIG_PREFIX[3] = { 0x55, 0x48, 0x89 }; /* push rbp; mov rbp,... */

/* ============================================================================
 * B5 — Debug auth bypass (fw 9.40 image base 0x01000000)
 * ----------------------------------------------------------------------------
 * Trophy 2 has a DEBUG API path (sceNpTrophy2SystemDebugUnlockTrophy) that
 * allows force-unlock of specific trophies. This is what would need if the
 * game's UDS callback never fires (= "UniversalDataSystem registration
 * failed errcode=0x8094000f" seen in klog for Astro Bot dumps).
 *
 * The daemon-side handler for IPMI cmd 0x90018 (DebugUnlockTrophy) is
 * FUN_01ce1490 in SceShellCore. It gates on FUN_019f0660 returning 1.
 *
 * FUN_019f0660 reads bit 30 of get_authinfo[12..15]:
 * uint FUN_019f0660(authctx) {
 * get_authinfo(ctx, buf);
 * return -(rc != 0) | ((*(uint*)(buf+12)) >> 30) & 1;
 * }
 * Returns 1 iff bit 30 is set = "debug authority". Retail processes (incl.
 * games) don't have this bit. PHU's SceShellUI inject doesn't either.
 *
 * Fix: patch FUN_019f0660 to always return 1. Enables ALL SystemDebug*
 * Trophy 2 APIs: DebugUnlockTrophy, DebugLockTrophy, GetTrophyData/Details,
 * RemoveTitleData/UserData/All, ListAllTitles. Note this also enables the
 * same APIs for non-trophy debug ops (~30 xrefs to FUN_019f0660 in the
 * 0x010106*-0x01010e* cluster). For offline JB use, this is acceptable.
 *
 * NB: Trophy 2 RegisterContext (cmd 0x90016) uses a SEPARATE auth check
 * FUN_019f1470 which is NOT touched by this patch — games pass it natively
 * because they have the "title-id capability" bit (matches 0x4800000000001010
 * style magic). The B1/B3/B4 patches are still needed for register flow.
 *
 * mov eax, 1; ret (6 bytes)
 * b8 01 00 00 00 c3
 * ============================================================================ */
/* r19.57 audit H3 — Legacy AUTH_BYPASS_* constants DELETED (hardcoded 9.40 VA
 * + plaintext patch payload). Use per-fw uint64_t b5_auth_bypass_va + the
 * B5_AUTH_BYPASS_PATCH / B5_AUTH_BYPASS_ORIG_PREFIX constants defined further
 * below (consumed by do_b5_auth_bypass_patch). */

/* ============================================================================
 * B5_LNC — LncManager attr bypass (fw 9.40 image base 0x01000000)
 * ----------------------------------------------------------------------------
 * Root cause discovery 2026-05-13 via RE:
 * runtime r15 RegisterContext returned 0x8094000F which initially thought
 * was ALREADY_INSTALLED. It's actually SCE_LNC_UTIL_ERROR_NOT_SYSTEM_PROCESS
 * emitted by FUN_015dab00 LncManager::getSceSysDirPath @ 0x015dad48.
 *
 * Check: if ((app->m_info.m_attr & 0x6) == 0) return 0x8094000F;
 * attr bits:
 * 0x02 = SCE_LNC_APP_ATTR_LAUNCHED_BY_DEBUGGER
 * 0x04 = SCE_LNC_APP_ATTR_LAUNCHED_VIA_APPHOME (sideload/fpkg/dev)
 *
 * Retail games launched normally have attr == 0 → reject. This is the LAST
 * gate blocking trophy install on retail-launched titles. With B1+B3+B4+this
 * patch + Path A file copy (B7), daemon completes RegisterContext successfully.
 *
 * The trophy commit chain FUN_01d2b3f0 calls:
 * FUN_0162be40 → FUN_015dab00 getSceSysDirPath(appId, sceSysDir[0x400])
 * which must succeed (return 0) and fill sceSysDir for the daemon to find
 * /system_data/priv/appmeta/<TID>/npbind.dat.
 *
 * Disassembly @ 0x015dad03..0x015dad10:
 * F6 86 04 01 00 00 06 TEST byte [RSI+0x104], 0x6 (the attr check)
 * 74 1A JZ +0x1A → 0x015dad26 (error path: mov R13D, 0x8094000F)
 * 48 83 C6 10 ADD RSI, 0x10 (success path begins)
 *...
 *
 * Patch: NOP NOP the JZ at 0x015dad0a → success path always executes.
 * TEST instruction still runs (harmless — sets ZF flag, no side effects).
 * Buffer fill happens in success block. R13D stays 0 (initial value).
 * Function returns 0 = success → daemon receives valid sceSysDir path.
 *
 * 74 1A → 90 90 (NOP NOP, 2 bytes, instruction-aligned)
 *
 * Verified by RE: no other attr-dependent checks elsewhere in this
 * function. Patch is minimal-impact; only affects this one gate. Other
 * ~120 LNC sites that return 0x8094000F are NOT touched.
 * ============================================================================ */
static constexpr uintptr_t SHELLCORE_LNC_ATTR_BYPASS_VA = 0x015dad0aUL;
static constexpr uint8_t LNC_ATTR_BYPASS_PATCH[2] = { 0x90, 0x90 }; /* NOP NOP (short JZ) */
static constexpr uint8_t LNC_ATTR_BYPASS_ORIG[2] = { 0x74, 0x1A }; /* JZ +0x1A → error (9.40/7.61/8.00) */
/* r19.28 — fw 4.03 uses LONG JZ (0F 84 rel32) instead of SHORT JZ (74 rel8).
 * Function FUN_0143da30 on 4.03 has the LNC attr check at 0x0143db4c with
 * pre-bytes `0F 84 86 00 00 00` (= JZ +0x86 forward). Need 6-NOP patch. */
static constexpr uint8_t LNC_ATTR_BYPASS_LONG_SIG[2] = { 0x0F, 0x84 }; /* long JZ opcode */
static constexpr uint8_t LNC_ATTR_BYPASS_LONG_PATCH[6] = { 0x90,0x90,0x90,0x90,0x90,0x90 };

/* ============================================================================
 * fw guard — RE'd offsets are 9.40 specific
 * ============================================================================ */
static bool fw_is_supported(void) {
    /* r19.4 — table lookup. Returns true if current fw has an entry in
     * g_trophy_fw_table[] (= RE'd offsets baked in). Add a new row
     * for each new fw after RE'ing the 8 offsets. */
    return get_fw_offsets != NULL;
}

/* ============================================================================
 * CSV whitelist parser (improved from Phase A: strips trailing token spaces)
 * ============================================================================ */
static int trophy_titleid_in_whitelist(const char *titleid) {
    const char *w = g_phu_cfg.trophy_unlock_titleids;
    if (!w || !w[0]) return 1;
    if (!titleid || !titleid[0]) return 0;

    const char *p = w;
    while (*p) {
        while (*p == ' ' || *p == ',') p++;
        if (!*p) break;
        const char *end = p;
        while (*end && *end != ',') end++;
        size_t len = (size_t)(end - p);
        /* Trim trailing whitespace within a token (Phase A audit fix). */
        while (len > 0 && (p[len - 1] == ' ' || p[len - 1] == '\t')) len--;
        if (len > 0 && len <= 15 && strncmp(p, titleid, len) == 0 && titleid[len] == 0) {
            return 1;
        }
        p = end;
    }
    return 0;
}

/* r19.56 hotfix-3 — trophy_skip_titleids CSV blacklist.
 * Returns 1 if titleid is in skip list (= PHU never touches SceShellCore for this game),
 * 0 if not (= normal flow). Empty cfg = always returns 0 (no impact). */
static int trophy_titleid_in_skiplist(const char *titleid) {
    const char *w = g_phu_cfg.trophy_skip_titleids;
    if (!w || !w[0]) return 0;
    if (!titleid || !titleid[0]) return 0;

    const char *p = w;
    while (*p) {
        while (*p == ' ' || *p == ',') p++;
        if (!*p) break;
        const char *end = p;
        while (*end && *end != ',') end++;
        size_t len = (size_t)(end - p);
        while (len > 0 && (p[len - 1] == ' ' || p[len - 1] == '\t')) len--;
        if (len > 0 && len <= 15 && strncmp(p, titleid, len) == 0 && titleid[len] == 0) {
            return 1;
        }
        p = end;
    }
    return 0;
}

/* ============================================================================
 * Probe: which image base matches the SceShellCore runtime layout ?
 * Returns the matching candidate (0x01000000 or 0x00000000), or UINTPTR_MAX
 * if neither yields "AAAA00000" at the expected slot[0] VA.
 * ============================================================================ */
static uintptr_t probe_image_base(pid_t shellcore_pid, uintptr_t shellcore_base) {
    /* r19.4 — per-fw lookup. fw_is_supported gate upstream guarantees e != NULL. */
    const phu_trophy_fw_offsets_t *e = get_fw_offsets;
    if (!e) return (uintptr_t)-1;
    for (size_t i = 0; i < sizeof(IMAGE_BASE_CANDIDATES) / sizeof(IMAGE_BASE_CANDIDATES[0]); i++) {
        uintptr_t cand = IMAGE_BASE_CANDIDATES[i];
        uintptr_t va = shellcore_base + (e->aaaa_slots[0] - cand);
        char buf[10] = {0};
        if (!prw::proc_read(shellcore_pid, va, buf, 9)) {
            klog_printf("[trophy] B1 probe: image_base=0x%lx miss (va=0x%lx read fail)\n",
                        cand, va);
            continue;
        }
        /* Two valid hits:
         * - AAAA00000 → SceShellCore reverted (just-restarted or fresh), need re-patch
         * - ZZZZZZZZZ → already patched, this candidate base is correct
         * Both confirm the candidate image base is right; differ only in re-apply intent. */
        if (memcmp(buf, AAAA_ORIGINAL, 9) == 0) {
            klog_printf("[trophy] B1 probe: image_base=0x%lx MATCH AAAA (va=0x%lx → re-patch)\n",
                        cand, va);
            return cand;
        }
        if (memcmp(buf, AAAA_PATCHED, 9) == 0) {
            klog_printf("[trophy] B1 probe: image_base=0x%lx MATCH ZZZZ (va=0x%lx → already patched)\n",
                        cand, va);
            return cand;
        }
        klog_printf("[trophy] B1 probe: image_base=0x%lx miss (va=0x%lx got '%.9s')\n",
                    cand, va, buf);
    }
    return (uintptr_t)-1;
}

/* ============================================================================
 * Core: DMAP-patch the 4 SceShellCore strings.
 * Returns count of successful patches (0..4).
 * ============================================================================ */
static int do_daemon_patch(pid_t shellcore_pid, uintptr_t shellcore_base,
                           uintptr_t image_base, bool verify_pre) {
    /* r19.4 — per-fw lookup. fw_is_supported gate upstream guarantees e != NULL. */
    const phu_trophy_fw_offsets_t *e = get_fw_offsets;
    if (!e) return 0;
    int success = 0;
    for (int i = 0; i < 4; i++) {
        uintptr_t va = shellcore_base + (e->aaaa_slots[i] - image_base);
        char buf[10] = {0};

        /* Pre-verify (optional, only on first patch — skip on re-apply since
         * the patched value "ZZZZZZZZZ" is also a valid found state). */
        if (verify_pre) {
            if (!prw::proc_read(shellcore_pid, va, buf, 9)) {
                klog_printf("[trophy] B1 read FAIL @ slot %d (va=0x%lx)\n", i, va);
                phu_diag_log("trophy B1 read FAIL slot=%d va=0x%lx", i, va);
                continue;
            }
            if (memcmp(buf, AAAA_ORIGINAL, 9) != 0) {
                klog_printf("[trophy] B1 slot %d unexpected content '%.9s' (expected '%s') — "
                            "skip, may already be patched or fw offset wrong\n",
                            i, buf, AAAA_ORIGINAL);
                phu_diag_log("trophy B1 slot=%d unexpected '%.9s'", i, buf);
                continue;
            }
        }

        /* r19.32 — save pre-patch bytes for rollback at game-vanish. */
        rollback_record(shellcore_pid, va, 10);

        /* Write 10 bytes: 9 chars + null terminator (same size as original). */
        if (!prw::proc_write(shellcore_pid, va, AAAA_PATCHED, 10)) {
            klog_printf("[trophy] B1 write FAIL @ slot %d (va=0x%lx)\n", i, va);
            phu_diag_log("trophy B1 write FAIL slot=%d va=0x%lx", i, va);
            continue;
        }

        /* Post-verify read-back. */
        memset(buf, 0, sizeof(buf));
        if (!prw::proc_read(shellcore_pid, va, buf, 9)) {
            klog_printf("[trophy] B1 verify-read FAIL @ slot %d\n", i);
            continue;
        }
        if (memcmp(buf, AAAA_PATCHED, 9) != 0) {
            klog_printf("[trophy] B1 verify MISMATCH @ slot %d: '%.9s' (expected '%s')\n",
                        i, buf, AAAA_PATCHED);
            phu_diag_log("trophy B1 verify MISMATCH slot=%d got '%.9s'", i, buf);
            continue;
        }

        /* Force daemon-side dcache flush. DMAP writes bypass the daemon CPU
         * core's L1/L2 dcache: the physical page reflects new bytes but the
         * daemon may still serve stale "AAAA00000" from its cache on a
         * different core. kernel_mprotect triggers TLB shootdown + dcache
         * sync, same pattern as B3/B4. Without this, multi-core race on first
         * post-patch trophy-register call returns stale gate result. */
        int mp = kernel_mprotect(shellcore_pid, (intptr_t)(va & ~0xFFFUL), 0x1000,
                                 PROT_READ);
        if (mp != 0) {
            klog_printf("[trophy] B1 kernel_mprotect flush rc=%d (non-fatal) @ slot %d\n", mp, i);
        }

        klog_printf("[trophy] B1 patched slot %d: va=0x%lx '%s' -> '%s' OK\n",
                    i, va, AAAA_ORIGINAL, AAAA_PATCHED);
        success++;
    }
    return success;
}

/* ============================================================================
 * B3 — Patch the 2 SceShellCore crypto entry points to `xor eax,eax; ret`.
 * Bypasses AES validation of npbind.dat entries → trophy register succeeds.
 * Returns count of successful patches (0..2).
 * ============================================================================ */
static int do_crypto_bypass_patch(pid_t shellcore_pid, uintptr_t shellcore_base,
                                  uintptr_t image_base) {
    /* r19.4 — per-fw lookup. fw_is_supported gate upstream guarantees e != NULL. */
    const phu_trophy_fw_offsets_t *e = get_fw_offsets;
    if (!e) return 0;
    /* r19.31 — B3 disabled-by-design (crypto_bypass[0]==0) means this fw has Path A
     * file loader sabotage risk if patched. Two scenarios:
     * 1. Cronos 10.01: Sony auto-prepares files → B7 is redundant → KEEP gate SKIP
     * (returns 0 to preserve r19.26 working behavior — don't touch what works !)
     * 2. Pre-Cronos with B3 disabled (e.g., 8.00): no auto-prepare, need B7 to copy
     * → return 2 (= "done") so apply_per_game gate passes for B7+B2+B6.
     * The pre-Cronos / Cronos distinction is empirical: 10.01 is the only Cronos fw
     * currently supported that has B3 disabled. */
    if (e->crypto_bypass[0] == 0 && e->crypto_bypass[1] == 0) {
        bool is_cronos = (e->fw_label && (strcmp(e->fw_label, "10.00") == 0 ||
                                          strcmp(e->fw_label, "10.01") == 0 ||
                                          strcmp(e->fw_label, "10.20") == 0 ||
                                          strcmp(e->fw_label, "11.00") == 0 ||
                                          strcmp(e->fw_label, "11.20") == 0 ||
                                          strcmp(e->fw_label, "11.60") == 0 ||
                                          strcmp(e->fw_label, "12.00") == 0 ||
                                          strcmp(e->fw_label, "12.70") == 0));
        if (is_cronos) {
            klog_printf("[trophy] B3 disabled-by-design for fw '%s' (Cronos era) — Sony auto-prepares, "
                        "gate SKIPS B7 (mirrors r19.26 10.01 working behavior)\n",
                        e->fw_label);
            phu_diag_log("trophy B3 disabled Cronos fw=%s (gate skips B7, Sony auto-prepare handles)",
                         e->fw_label);
            return 0; /* Cronos: gate skips B7+B2+B6, daemon's auto-prepare handles */
        }
        klog_printf("[trophy] B3 disabled-by-design for fw '%s' — skip patches, "
                    "mark done so gate passes for B7+B2+B6 (pre-Cronos needs B7)\n",
                    e->fw_label ? e->fw_label: "?");
        phu_diag_log("trophy B3 disabled-by-design fw=%s (gate passes for B7+B2+B6)",
                     e->fw_label ? e->fw_label: "?");
        return 2; /* Pre-Cronos: caller sets g_b3_full_done = true → gate passes */
    }
    int success = 0;
    constexpr size_t N = 2; /* crypto_bypass[2] array size in phu_trophy_fw_offsets_t */
    for (size_t i = 0; i < N; i++) {
        uintptr_t va = shellcore_base + (e->crypto_bypass[i] - image_base);
        uint8_t pre[3] = {0};
        uint8_t post[3] = {0};

        /* Pre-read for sanity + diag. */
        if (!prw::proc_read(shellcore_pid, va, pre, 3)) {
            klog_printf("[trophy] B3 read FAIL @ slot %zu (va=0x%lx)\n", i, va);
            phu_diag_log("trophy B3 read FAIL slot=%zu va=0x%lx", i, va);
            continue;
        }
        /* Expect function prologue `55 48 89` (= push rbp; mov rbp,...) */
        if (pre[0] != 0x55 || pre[1] != 0x48 || pre[2] != 0x89) {
            /* Already patched or fw mismatch */
            if (pre[0] == CRYPTO_BYPASS_PATCH[0] &&
                pre[1] == CRYPTO_BYPASS_PATCH[1] &&
                pre[2] == CRYPTO_BYPASS_PATCH[2]) {
                klog_printf("[trophy] B3 slot %zu already patched (va=0x%lx) — skip\n", i, va);
                success++;
                continue;
            }
            klog_printf("[trophy] B3 slot %zu unexpected prologue %02x %02x %02x (va=0x%lx) — "
                        "skip, fw offset wrong\n", i, pre[0], pre[1], pre[2], va);
            phu_diag_log("trophy B3 slot=%zu unexpected %02x%02x%02x", i, pre[0], pre[1], pre[2]);
            continue;
        }

        /* r19.32 — save pre-patch bytes for rollback at game-vanish. */
        rollback_record(shellcore_pid, va, 3);

        /* DMAP write the bypass patch. */
        if (!prw::proc_write(shellcore_pid, va, CRYPTO_BYPASS_PATCH, 3)) {
            klog_printf("[trophy] B3 write FAIL @ slot %zu (va=0x%lx)\n", i, va);
            phu_diag_log("trophy B3 write FAIL slot=%zu va=0x%lx", i, va);
            continue;
        }

        /* Force µop cache flush via kernel_mprotect (per
         * feedback_phu_dmap_write_needs_mprotect_flush). Re-apply
         * PROT_RX (default for.text) — the side effect is the kernel
         * invalidates the cached instruction decode for that page. */
        int mp = kernel_mprotect(shellcore_pid, (intptr_t)(va & ~0xFFFUL), 0x1000,
                                  PROT_READ | PROT_EXEC);
        if (mp != 0) {
            /* Non-fatal — write may still take effect via DMAP coherency,
             * just slower or unreliable across multiple TLBs. */
            klog_printf("[trophy] B3 mprotect WARN slot %zu (va=0x%lx page=0x%lx ret=%d)\n",
                        i, va, va & ~0xFFFUL, mp);
        }

        /* Post-verify read-back. */
        if (!prw::proc_read(shellcore_pid, va, post, 3)) {
            klog_printf("[trophy] B3 verify-read FAIL @ slot %zu\n", i);
            continue;
        }
        if (post[0] != CRYPTO_BYPASS_PATCH[0] ||
            post[1] != CRYPTO_BYPASS_PATCH[1] ||
            post[2] != CRYPTO_BYPASS_PATCH[2]) {
            klog_printf("[trophy] B3 verify MISMATCH @ slot %zu: %02x %02x %02x (want %02x %02x %02x)\n",
                        i, post[0], post[1], post[2],
                        CRYPTO_BYPASS_PATCH[0], CRYPTO_BYPASS_PATCH[1], CRYPTO_BYPASS_PATCH[2]);
            phu_diag_log("trophy B3 verify MISMATCH slot=%zu got %02x%02x%02x", i,
                         post[0], post[1], post[2]);
            continue;
        }

        klog_printf("[trophy] B3 patched slot %zu: va=0x%lx %02x%02x%02x -> %02x%02x%02x OK\n",
                    i, va, pre[0], pre[1], pre[2], post[0], post[1], post[2]);
        success++;
    }
    return success;
}

/* ============================================================================
 * B4 — Patch FUN_017266c0 (app inventory check) to force-write category = 2
 * and return 0. Bypasses the "is this app registered" gate that
 * silently blocks trophy registration for raw DUMPS (not pkg-installed).
 * Returns 1 on success, 0 on failure.
 * ============================================================================ */
static int do_app_inventory_bypass_patch(pid_t shellcore_pid, uintptr_t shellcore_base,
                                         uintptr_t image_base) {
    /* r19.4 — per-fw lookup. */
    const phu_trophy_fw_offsets_t *e = get_fw_offsets;
    if (!e) return 0;
    /* r19.38 — skip-if-zero for fws where B4 is disabled-by-design (e.g. 12.00 first ship
     * where the proper wrapper was not yet RE'd). Return 1 = "done" so apply_per_game
     * gate considers B4 satisfied and proceeds to B5+B2+B6+B7 chain. */
    if (e->app_inventory_va == 0) {
        klog_printf("[trophy] B4 disabled-by-design for fw '%s' — skip (mark done)\n",
                    e->fw_label ? e->fw_label: "?");
        phu_diag_log("trophy B4 disabled-by-design fw=%s",
                     e->fw_label ? e->fw_label: "?");
        return 1;
    }
    uintptr_t va = shellcore_base + (e->app_inventory_va - image_base);
    uint8_t pre[10] = {0};
    uint8_t post[10] = {0};

    /* Pre-read for sanity + diag. */
    if (!prw::proc_read(shellcore_pid, va, pre, sizeof(pre))) {
        klog_printf("[trophy] B4 read FAIL (va=0x%lx)\n", va);
        phu_diag_log("trophy B4 read FAIL va=0x%lx", va);
        return 0;
    }
    /* Expect function prologue starts with `55 48 89` */
    if (pre[0] != APP_INVENTORY_ORIG_PREFIX[0] ||
        pre[1] != APP_INVENTORY_ORIG_PREFIX[1] ||
        pre[2] != APP_INVENTORY_ORIG_PREFIX[2]) {
        /* Already patched check */
        if (memcmp(pre, APP_INVENTORY_PATCH, sizeof(APP_INVENTORY_PATCH)) == 0) {
            klog_printf("[trophy] B4 already patched (va=0x%lx) — skip\n", va);
            return 1;
        }
        klog_printf("[trophy] B4 unexpected prologue %02x %02x %02x (va=0x%lx) — "
                    "skip, fw offset wrong\n", pre[0], pre[1], pre[2], va);
        phu_diag_log("trophy B4 unexpected %02x%02x%02x", pre[0], pre[1], pre[2]);
        return 0;
    }

    /* r19.32 — save pre-patch bytes for rollback at game-vanish. */
    rollback_record(shellcore_pid, va, sizeof(APP_INVENTORY_PATCH));

    /* DMAP write the bypass patch. */
    if (!prw::proc_write(shellcore_pid, va, APP_INVENTORY_PATCH, sizeof(APP_INVENTORY_PATCH))) {
        klog_printf("[trophy] B4 write FAIL (va=0x%lx)\n", va);
        phu_diag_log("trophy B4 write FAIL va=0x%lx", va);
        return 0;
    }

    /* Force µop cache flush via kernel_mprotect. */
    int mp = kernel_mprotect(shellcore_pid, (intptr_t)(va & ~0xFFFUL), 0x1000,
                              PROT_READ | PROT_EXEC);
    if (mp != 0) {
        klog_printf("[trophy] B4 mprotect WARN (va=0x%lx page=0x%lx ret=%d)\n",
                    va, va & ~0xFFFUL, mp);
    }

    /* Post-verify read-back. */
    if (!prw::proc_read(shellcore_pid, va, post, sizeof(post))) {
        klog_printf("[trophy] B4 verify-read FAIL\n");
        return 0;
    }
    if (memcmp(post, APP_INVENTORY_PATCH, sizeof(APP_INVENTORY_PATCH)) != 0) {
        klog_printf("[trophy] B4 verify MISMATCH @ va=0x%lx\n", va);
        phu_diag_log("trophy B4 verify MISMATCH va=0x%lx", va);
        return 0;
    }

    klog_printf("[trophy] B4 patched FUN_017266c0: va=0x%lx app-inventory bypass OK\n", va);
    phu_diag_log("trophy B4 patched va=0x%lx", va);
    return 1;
}

/* ============================================================================
 * B5 — Patch FUN_019f0660 (auth check for SystemDebug* APIs) to always
 * return 1. Enables sceNpTrophy2SystemDebugUnlockTrophy and other debug
 * APIs for any caller (PHU, game, etc.).
 * Returns 1 on success, 0 on failure.
 * ============================================================================ */
/* r19.57 audit H3 — Legacy do_auth_bypass_patch DELETED.
 * Previously suppressed via (void)do_auth_bypass_patch but kept a hardcoded
 * 9.40-only VA (0x019f0660) plaintext in.rodata + a fully-functional patch
 * routine reachable by any accidental refactor. Replaced everywhere by
 * do_b5_auth_bypass_patch which uses the per-fw b5_auth_bypass_va field */

/* ============================================================================
 * B5_LNC — Patch FUN_015dab00 LncManager::getSceSysDirPath @ 0x015dad0a:
 * `74 1A` (JZ +0x1A to error) → `90 90` (NOP NOP, fall through to success).
 * Bypasses the (app->m_info.m_attr & 0x6) == 0 check that returns
 * 0x8094000F = SCE_LNC_UTIL_ERROR_NOT_SYSTEM_PROCESS for retail-launched
 * apps. This is the final daemon-side gate blocking trophy install for
 * retail dumps. Returns 1 on success, 0 on failure.
 * ============================================================================ */
static int do_lnc_attr_bypass_patch(pid_t shellcore_pid, uintptr_t shellcore_base,
                                    uintptr_t image_base) {
    /* r19.4 — per-fw lookup. */
    const phu_trophy_fw_offsets_t *e = get_fw_offsets;
    if (!e) return 0;
    uintptr_t va = shellcore_base + (e->lnc_attr_va - image_base);

    /* r19.28 — read 6 bytes to detect both SHORT (74 rel8) and LONG (0F 84 rel32) JZ.
     * 9.40/7.61/8.00 use short JZ `74 1A` (2 bytes), patch 2× NOP.
     * 4.03 uses long JZ `0F 84 rel32` (6 bytes), patch 6× NOP. */
    uint8_t pre6[6] = {0};
    if (!prw::proc_read(shellcore_pid, va, pre6, sizeof(pre6))) {
        klog_printf("[trophy] B5_LNC read FAIL (va=0x%lx)\n", va);
        phu_diag_log("trophy B5_LNC read FAIL va=0x%lx", va);
        return 0;
    }
    /* Already-patched detection: check first 2 bytes (covers both short+long NOPed). */
    if (memcmp(pre6, LNC_ATTR_BYPASS_PATCH, sizeof(LNC_ATTR_BYPASS_PATCH)) == 0) {
        klog_printf("[trophy] B5_LNC already patched (va=0x%lx) — skip\n", va);
        return 1;
    }

    /* Determine JZ form: SHORT (74 rel8) for 9.40/7.61/8.00/10.01/12.00, LONG (0F 84 rel32) for 4.03/5.50.
     * r19.38 — match opcode only (pre6[0] == 0x74) for short JZ, since the rel8 displacement
     * varies per fw (9.40=0x1A, 12.00=0x60, etc.) and NOP both bytes regardless. */
    bool is_short_jz = (pre6[0] == 0x74);
    bool is_long_jz = (memcmp(pre6, LNC_ATTR_BYPASS_LONG_SIG, 2) == 0);

    if (!is_short_jz && !is_long_jz) {
        klog_printf("[trophy] B5_LNC unexpected pre bytes %02x %02x %02x %02x %02x %02x "
                    "(expected 74 XX or 0F 84 XX XX XX XX) — fw offset wrong, abort\n",
                    pre6[0], pre6[1], pre6[2], pre6[3], pre6[4], pre6[5]);
        phu_diag_log("trophy B5_LNC pre-mismatch %02x%02x%02x%02x%02x%02x",
                     pre6[0], pre6[1], pre6[2], pre6[3], pre6[4], pre6[5]);
        return 0;
    }

    const uint8_t *patch_bytes = is_short_jz ? LNC_ATTR_BYPASS_PATCH: LNC_ATTR_BYPASS_LONG_PATCH;
    size_t patch_size = is_short_jz ? sizeof(LNC_ATTR_BYPASS_PATCH)
: sizeof(LNC_ATTR_BYPASS_LONG_PATCH);

    /* r19.32 — save pre-patch bytes for rollback at game-vanish.
     * Short JZ = 2 bytes, long JZ = 6 bytes (use detected patch_size). */
    rollback_record(shellcore_pid, va, patch_size);

    if (!prw::proc_write(shellcore_pid, va, patch_bytes, patch_size)) {
        klog_printf("[trophy] B5_LNC write FAIL (va=0x%lx)\n", va);
        phu_diag_log("trophy B5_LNC write FAIL va=0x%lx", va);
        return 0;
    }

    int mp = kernel_mprotect(shellcore_pid, (intptr_t)(va & ~0xFFFUL), 0x1000,
                             PROT_READ | PROT_EXEC);
    if (mp != 0) {
        klog_printf("[trophy] B5_LNC mprotect WARN (va=0x%lx page=0x%lx ret=%d)\n",
                    va, va & ~0xFFFUL, mp);
    }

    uint8_t post6[6] = {0};
    if (!prw::proc_read(shellcore_pid, va, post6, patch_size)) {
        klog_printf("[trophy] B5_LNC verify-read FAIL\n");
        return 0;
    }
    if (memcmp(post6, patch_bytes, patch_size) != 0) {
        klog_printf("[trophy] B5_LNC verify MISMATCH @ va=0x%lx\n", va);
        phu_diag_log("trophy B5_LNC verify MISMATCH va=0x%lx", va);
        return 0;
    }

    klog_printf("[trophy] B5_LNC patched: va=0x%lx %s → %zu× NOP "
                "(LncManager attr & 0x6 gate bypassed) OK\n", va,
                is_short_jz ? "'74 1A'": "'0F 84 rel32'", patch_size);
    phu_diag_log("trophy B5_LNC patched va=0x%lx (%s, %zu bytes)",
                 va, is_short_jz ? "short": "long", patch_size);
    return 1;
}


/* ============================================================================
 * B8 — Force path B in trophy register chain (r19.6 fix for rc=0x8055390c on 10.01)
 * ----------------------------------------------------------------------------
 * On fw 10.01, Sony defaulted FUN_01d1c230's flag byte at [arg+8] to 0.
 * Path A (FUN_01aede40 = B3-patched) is taken → caller FUN_01d1c650 reads
 * uninitialized local_48 → returns 0x8055390c. Patch FUN_01d1c230 to always
 * return 1 → forces path B (FUN_01a8fc60 reads /user/.../np_bind_local/trophy2/
 * npbind_local.json) → matches 9.40 default behavior where trophy install works.
 *
 * Original bytes (10.01): `0f b6 47 08 c3` = movzx eax, byte [rdi+8]; ret
 * Patch (6 bytes): `b8 01 00 00 00 c3` = mov eax, 1; ret
 * 1 byte of original padding (cc) gets overwritten — safe (was int3 trap).
 *
 * Per-fw gate: skip cleanly if e->b8_path_b_force_va == 0 (= 9.40/7.61 don't
 * need this, runtime byte already = 1). Returns 1 success (= patched OR skip
 * because not needed), 0 fail (= read/write/verify error on a fw that asked).
 * ============================================================================ */
static constexpr uint8_t MOVZX_BYTE_FORCE1_PATCH[6] = { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 };
/* Pattern: movzx eax, byte [rdi+disp8]; ret = 0F B6 47 NN C3 (5 bytes).
 * disp8 differs per patch site (B8 = +0x08, B9 = +0x70, etc.). */

/* Generic byte-getter → return-1 patch helper. Used by B8 (FUN_01d1c230, disp +0x08)
 * and B9 (FUN_01d808a0, disp +0x70). Returns 1 if patched OR skip-clean,
 * 0 if read/write/verify fails on a fw that needed the patch. */
static int do_byte_getter_force1_patch(pid_t shellcore_pid, uintptr_t shellcore_base,
                                       uintptr_t image_base,
                                       uintptr_t patch_va_static,
                                       uint8_t expected_disp,
                                       const char *step_label) {
    if (patch_va_static == 0) {
        klog_printf("[trophy] %s skip: fw not affected (va=0)\n", step_label);
        return 1;
    }

    uintptr_t va = shellcore_base + (patch_va_static - image_base);
    uint8_t pre[6] = {0};
    uint8_t post[6] = {0};

    if (!prw::proc_read(shellcore_pid, va, pre, 5)) {
        klog_printf("[trophy] %s read FAIL (va=0x%lx)\n", step_label, va);
        phu_diag_log("trophy %s read FAIL va=0x%lx", step_label, va);
        return 0;
    }
    /* Already-patched detection */
    if (pre[0] == MOVZX_BYTE_FORCE1_PATCH[0] && pre[1] == MOVZX_BYTE_FORCE1_PATCH[1]) {
        klog_printf("[trophy] %s already patched (va=0x%lx) — skip\n", step_label, va);
        return 1;
    }
    /* Expect movzx eax, byte [rdi+disp8]; ret = 0f b6 47 NN c3 */
    if (pre[0] != 0x0F || pre[1] != 0xB6 || pre[2] != 0x47 ||
        pre[3] != expected_disp || pre[4] != 0xC3) {
        klog_printf("[trophy] %s unexpected pre bytes %02x %02x %02x %02x %02x "
                    "(expected 0f b6 47 %02x c3) — abort\n", step_label,
                    pre[0], pre[1], pre[2], pre[3], pre[4], expected_disp);
        phu_diag_log("trophy %s pre-mismatch %02x%02x%02x%02x%02x", step_label,
                     pre[0], pre[1], pre[2], pre[3], pre[4]);
        return 0;
    }

    rollback_record(shellcore_pid, va, sizeof(MOVZX_BYTE_FORCE1_PATCH));
    if (!prw::proc_write(shellcore_pid, va,
                         MOVZX_BYTE_FORCE1_PATCH, sizeof(MOVZX_BYTE_FORCE1_PATCH))) {
        klog_printf("[trophy] %s write FAIL (va=0x%lx)\n", step_label, va);
        return 0;
    }

    int mp = kernel_mprotect(shellcore_pid, (intptr_t)(va & ~0xFFFUL), 0x1000,
                              PROT_READ | PROT_EXEC);
    if (mp != 0) {
        klog_printf("[trophy] %s mprotect WARN ret=%d\n", step_label, mp);
    }

    if (!prw::proc_read(shellcore_pid, va, post, sizeof(post))) {
        klog_printf("[trophy] %s verify-read FAIL\n", step_label);
        return 0;
    }
    if (memcmp(post, MOVZX_BYTE_FORCE1_PATCH, sizeof(MOVZX_BYTE_FORCE1_PATCH)) != 0) {
        klog_printf("[trophy] %s verify MISMATCH @ va=0x%lx\n", step_label, va);
        return 0;
    }

    klog_printf("[trophy] %s patched: va=0x%lx → mov eax,1;ret OK\n", step_label, va);
    phu_diag_log("trophy %s patched va=0x%lx", step_label, va);
    return 1;
}

static int do_b8_path_b_force_patch(pid_t shellcore_pid, uintptr_t shellcore_base,
                                    uintptr_t image_base) {
    const phu_trophy_fw_offsets_t *e = get_fw_offsets;
    if (!e) return 0;
    /* B8 = FUN_01d1c230 = movzx eax, byte [rdi+0x08]; ret */
    return do_byte_getter_force1_patch(shellcore_pid, shellcore_base, image_base,
                                       e->b8_path_b_force_va, 0x08,
                                       "B8 (path-B force, FUN_01d1c230)");
}

static int do_b9_path_b_vtable_patch(pid_t shellcore_pid, uintptr_t shellcore_base,
                                     uintptr_t image_base) {
    const phu_trophy_fw_offsets_t *e = get_fw_offsets;
    if (!e) return 0;
    /* B9 = FUN_01d808a0 = movzx eax, byte [rdi+0x70]; ret */
    return do_byte_getter_force1_patch(shellcore_pid, shellcore_base, image_base,
                                       e->b9_path_b_vtable_va, 0x70,
                                       "B9 (path-B vtable, FUN_01d808a0)");
}

/* ============================================================================
 * B10 — Path B nuclear bypass: FUN_01a8fc60 entry force success+NULL.
 *
 * Patches the function entry to immediately return 0 (success) with *param_4
 * = NULL. This bypasses all path B internal checks (vtable[2] = B9-fix,
 * DAT_02f52010 NULL check, inner vtable[5], file read FUN_01a98280) in a
 * single 6-byte patch.
 *
 * Patch (6 bytes):
 * 31 c0 xor eax, eax; return 0
 * 48 89 01 mov [rcx], rax; *param_4 = NULL (System V ABI: rcx=arg4)
 * c3 ret
 *
 * Caller FUN_01d1c650 path B branch handles NULL output gracefully:
 * FUN_01d1d450 (downstream consumer) checks `if (lVar1 != 0)` before AddRef.
 *
 * Original prologue (10.01): `55 48 89 e5 41 57 41 56 41 55` (push rbp;
 * mov rbp,rsp; push r15/r14/r13). Overwrite the first 6 bytes; remaining
 * `41 56 41 55` is orphan code never executed (ret early). No stack imbalance
 * (don't push anything, so no pop needed).
 *
 * Per-fw gate: skip if e->b10_path_b_entry_va == 0 (9.40/7.61 don't need it).
 * ============================================================================ */
static constexpr uint8_t B10_PATH_B_ENTRY_PATCH[6] = {
    0x31, 0xC0, /* xor eax, eax */
    0x48, 0x89, 0x01, /* mov [rcx], rax */
    0xC3 /* ret */
};
static constexpr uint8_t B10_PATH_B_ENTRY_ORIG_PREFIX[4] = { 0x55, 0x48, 0x89, 0xE5 }; /* push rbp; mov rbp, rsp */

/* ============================================================================
 * B5 — Debug auth bypass: FUN_019e84e0 (10.01) / FUN_019f0660 (9.40) force return 1.
 *
 * Enables Trophy 2 Debug APIs (sceNpTrophy2SystemDebugUnlockTrophy + 30 other
 * DebugXxx functions). On 10.01, RegisterContext path A+B are dead-code → uses * SystemDebugUnlockTrophy as primary unlock path. Daemon-side gate
 * FUN_01cd63f0 calls FUN_019e84e0 == 1; B5 patches it to always return 1.
 *
 * Patch (6 bytes): b8 01 00 00 00 c3 = mov eax, 1; ret
 * Original prologue starts with 55 48 89 e5 (push rbp; mov rbp, rsp) — gets
 * overwritten cleanly, function returns immediately.
 *
 * KP risk: enabled Debug APIs in trophy daemon. On 9.40 skipped for
 * safety (= other ops could trigger panic). On 10.01 NEEDED because the
 * standard RegisterContext path is broken (= DebugUnlock is now primary).
 *
 * Per-fw gate: skip if b5_auth_bypass_va == 0 (= fw doesn't need DebugUnlock).
 * ============================================================================ */
static constexpr uint8_t B5_AUTH_BYPASS_PATCH[6] = {
    0xB8, 0x01, 0x00, 0x00, 0x00, /* mov eax, 1 */
    0xC3 /* ret */
};
static constexpr uint8_t B5_AUTH_BYPASS_ORIG_PREFIX[4] = { 0x55, 0x48, 0x89, 0xE5 }; /* push rbp; mov rbp, rsp */

static int do_b5_auth_bypass_patch(pid_t shellcore_pid, uintptr_t shellcore_base,
                                   uintptr_t image_base) {
    const phu_trophy_fw_offsets_t *e = get_fw_offsets;
    if (!e) return 0;
    if (e->b5_auth_bypass_va == 0) {
        klog_printf("[trophy] B5 skip: fw '%s' does not need debug auth bypass\n",
                    e->fw_label ? e->fw_label: "?");
        return 1; /* not-needed = success */
    }

    uintptr_t va = shellcore_base + (e->b5_auth_bypass_va - image_base);
    uint8_t pre[6] = {0};
    uint8_t post[6] = {0};

    if (!prw::proc_read(shellcore_pid, va, pre, sizeof(pre))) {
        klog_printf("[trophy] B5 read FAIL (va=0x%lx)\n", va);
        phu_diag_log("trophy B5 read FAIL va=0x%lx", va);
        return 0;
    }
    if (memcmp(pre, B5_AUTH_BYPASS_PATCH, 4) == 0) {
        klog_printf("[trophy] B5 already patched (va=0x%lx) — skip\n", va);
        return 1;
    }
    if (memcmp(pre, B5_AUTH_BYPASS_ORIG_PREFIX, sizeof(B5_AUTH_BYPASS_ORIG_PREFIX)) != 0) {
        klog_printf("[trophy] B5 unexpected pre bytes %02x %02x %02x %02x "
                    "(expected 55 48 89 e5) — abort\n",
                    pre[0], pre[1], pre[2], pre[3]);
        phu_diag_log("trophy B5 pre-mismatch %02x%02x%02x%02x",
                     pre[0], pre[1], pre[2], pre[3]);
        return 0;
    }

    /* r19.57 audit C2 — snapshot original bytes before patching so rollback
     * on game-vanish can restore SceShellCore to vanilla. Without this,
     * 10.01 sessions leave B5 patched permanently → next PS4 BC launch
     * may hit Sony's 0x80551618 cascade (= incident r19.32 was meant to fix). */
    rollback_record(shellcore_pid, va, sizeof(B5_AUTH_BYPASS_PATCH));

    if (!prw::proc_write(shellcore_pid, va,
                         B5_AUTH_BYPASS_PATCH, sizeof(B5_AUTH_BYPASS_PATCH))) {
        klog_printf("[trophy] B5 write FAIL (va=0x%lx)\n", va);
        return 0;
    }

    int mp = kernel_mprotect(shellcore_pid, (intptr_t)(va & ~0xFFFUL), 0x1000,
                              PROT_READ | PROT_EXEC);
    if (mp != 0) {
        klog_printf("[trophy] B5 mprotect WARN ret=%d\n", mp);
    }

    if (!prw::proc_read(shellcore_pid, va, post, sizeof(post))) {
        klog_printf("[trophy] B5 verify-read FAIL\n");
        return 0;
    }
    if (memcmp(post, B5_AUTH_BYPASS_PATCH, sizeof(B5_AUTH_BYPASS_PATCH)) != 0) {
        klog_printf("[trophy] B5 verify MISMATCH @ va=0x%lx\n", va);
        return 0;
    }

    klog_printf("[trophy] B5 patched: va=0x%lx auth bypass → mov eax,1;ret "
                "(enables SystemDebugUnlockTrophy + other Trophy 2 Debug APIs) OK\n", va);
    phu_diag_log("trophy B5 patched va=0x%lx (auth bypass)", va);
    return 1;
}

static int do_b10_path_b_entry_patch(pid_t shellcore_pid, uintptr_t shellcore_base,
                                     uintptr_t image_base) {
    const phu_trophy_fw_offsets_t *e = get_fw_offsets;
    if (!e) return 0;
    if (e->b10_path_b_entry_va == 0) {
        klog_printf("[trophy] B10 skip: fw '%s' does not need path-B entry bypass\n",
                    e->fw_label ? e->fw_label: "?");
        return 1; /* not-needed = success */
    }

    uintptr_t va = shellcore_base + (e->b10_path_b_entry_va - image_base);
    uint8_t pre[6] = {0};
    uint8_t post[6] = {0};

    if (!prw::proc_read(shellcore_pid, va, pre, sizeof(pre))) {
        klog_printf("[trophy] B10 read FAIL (va=0x%lx)\n", va);
        phu_diag_log("trophy B10 read FAIL va=0x%lx", va);
        return 0;
    }
    /* Already-patched detection */
    if (memcmp(pre, B10_PATH_B_ENTRY_PATCH, 4) == 0) { /* check first 4 bytes for partial match */
        klog_printf("[trophy] B10 already patched (va=0x%lx) — skip\n", va);
        return 1;
    }
    /* Expect standard x86_64 prologue starts (push rbp; mov rbp, rsp) */
    if (memcmp(pre, B10_PATH_B_ENTRY_ORIG_PREFIX, sizeof(B10_PATH_B_ENTRY_ORIG_PREFIX)) != 0) {
        klog_printf("[trophy] B10 unexpected pre bytes %02x %02x %02x %02x "
                    "(expected 55 48 89 e5) — abort\n",
                    pre[0], pre[1], pre[2], pre[3]);
        phu_diag_log("trophy B10 pre-mismatch %02x%02x%02x%02x",
                     pre[0], pre[1], pre[2], pre[3]);
        return 0;
    }

    rollback_record(shellcore_pid, va, sizeof(B10_PATH_B_ENTRY_PATCH));
    if (!prw::proc_write(shellcore_pid, va,
                         B10_PATH_B_ENTRY_PATCH, sizeof(B10_PATH_B_ENTRY_PATCH))) {
        klog_printf("[trophy] B10 write FAIL (va=0x%lx)\n", va);
        return 0;
    }

    int mp = kernel_mprotect(shellcore_pid, (intptr_t)(va & ~0xFFFUL), 0x1000,
                              PROT_READ | PROT_EXEC);
    if (mp != 0) {
        klog_printf("[trophy] B10 mprotect WARN ret=%d\n", mp);
    }

    if (!prw::proc_read(shellcore_pid, va, post, sizeof(post))) {
        klog_printf("[trophy] B10 verify-read FAIL\n");
        return 0;
    }
    if (memcmp(post, B10_PATH_B_ENTRY_PATCH, sizeof(B10_PATH_B_ENTRY_PATCH)) != 0) {
        klog_printf("[trophy] B10 verify MISMATCH @ va=0x%lx\n", va);
        return 0;
    }

    klog_printf("[trophy] B10 patched: va=0x%lx FUN_01a8fc60 → xor eax,eax;mov [rcx],rax;ret "
                "(bypass all path B internal checks, fixes rc=0x8055d20x cascade) OK\n", va);
    phu_diag_log("trophy B10 patched va=0x%lx (path-B entry bypass)", va);
    return 1;
}

/* ============================================================================
 * B12 r19.16 — Surgical JZ NOP inside FUN_01d1c520 (commId NULL check bypass).
 *
 * r19.15 attempted to patch FUN_01d1d320 (BindInfo::GetNpCommIdPtr) to always
 * return 1. This crashed beta tester console because OTHER Sony consumers of
 * FUN_01d1d320 dereferenced the fake `1` as a pointer → kernel panic.
 *
 * r19.16 SURGICAL: patch ONLY the JZ at 0x01d1c5ca inside FUN_01d1c520.
 * That JZ branches to the `MOV R14D, 0x8055391a` error path when commId is NULL.
 * NOP'ing it makes execution fall through to the success path which stores
 * the BindInfo pointer (local_40) in output — NULL commId is OK because the
 * function's caller doesn't dereference commId from this return.
 *
 * Original (2 bytes): 74 6A (JZ short +0x6A)
 * Patch (2 bytes): 90 90 (NOP NOP)
 *
 * No effect on FUN_01d1d320 itself → other consumers keep original NULL-aware
 * behavior → no cross-function crashes.
 *
 * Per-fw gate: skip if b12_commid_force_va == 0 (9.40/7.61 don't need it).
 * ============================================================================ */
static constexpr uint8_t B12_JZ_NOP_PATCH[2] = { 0x90, 0x90 }; /* NOP NOP */
static constexpr uint8_t B12_JZ_ORIG[2] = { 0x74, 0x6A }; /* JZ short +0x6A */

static int do_b12_commid_force_patch(pid_t shellcore_pid, uintptr_t shellcore_base,
                                     uintptr_t image_base) {
    const phu_trophy_fw_offsets_t *e = get_fw_offsets;
    if (!e) return 0;
    if (e->b12_commid_force_va == 0) {
        klog_printf("[trophy] B12 skip: fw '%s' does not need commId force\n",
                    e->fw_label ? e->fw_label: "?");
        return 1; /* not-needed = success */
    }

    uintptr_t va = shellcore_base + (e->b12_commid_force_va - image_base);
    uint8_t pre[2] = {0};
    uint8_t post[2] = {0};

    if (!prw::proc_read(shellcore_pid, va, pre, sizeof(pre))) {
        klog_printf("[trophy] B12 read FAIL (va=0x%lx)\n", va);
        phu_diag_log("trophy B12 read FAIL va=0x%lx", va);
        return 0;
    }
    /* Already-patched detection */
    if (pre[0] == 0x90 && pre[1] == 0x90) {
        klog_printf("[trophy] B12 already NOPed (va=0x%lx) — skip\n", va);
        return 1;
    }
    /* Expect JZ short +0x6A */
    if (memcmp(pre, B12_JZ_ORIG, sizeof(B12_JZ_ORIG)) != 0) {
        klog_printf("[trophy] B12 unexpected pre bytes %02x %02x "
                    "(expected 74 6A = JZ +0x6A) — abort\n",
                    pre[0], pre[1]);
        phu_diag_log("trophy B12 pre-mismatch %02x%02x", pre[0], pre[1]);
        return 0;
    }

    rollback_record(shellcore_pid, va, sizeof(B12_JZ_NOP_PATCH));
    if (!prw::proc_write(shellcore_pid, va,
                         B12_JZ_NOP_PATCH, sizeof(B12_JZ_NOP_PATCH))) {
        klog_printf("[trophy] B12 write FAIL (va=0x%lx)\n", va);
        phu_diag_log("trophy B12 write FAIL va=0x%lx", va);
        return 0;
    }

    int mp = kernel_mprotect(shellcore_pid, (intptr_t)(va & ~0xFFFUL), 0x1000,
                              PROT_READ | PROT_EXEC);
    if (mp != 0) {
        klog_printf("[trophy] B12 mprotect WARN ret=%d\n", mp);
    }

    if (!prw::proc_read(shellcore_pid, va, post, sizeof(post))) {
        klog_printf("[trophy] B12 verify-read FAIL\n");
        return 0;
    }
    if (memcmp(post, B12_JZ_NOP_PATCH, sizeof(B12_JZ_NOP_PATCH)) != 0) {
        klog_printf("[trophy] B12 verify MISMATCH @ va=0x%lx\n", va);
        return 0;
    }

    klog_printf("[trophy] B12 patched: va=0x%lx FUN_01d1c520 JZ → NOP NOP "
                "(bypass commId NULL check, fixes rc=0x8055391a, NO crash) OK\n", va);
    phu_diag_log("trophy B12 surgical NOP va=0x%lx (commId JZ bypass)", va);
    return 1;
}

/* ============================================================================
 * Public API (extern "C" wraps for C-callable linkage)
 * ============================================================================ */

/* ============================================================================
 * B13 r19.18 — Patch sce::np::User::GetUser in libSceNpManager (SceShellCore).
 *
 * Runtime diag r19.17 confirmed: FS scan /user/home/ finds uid=16 BUT daemon
 * still returns 0x80553917. RE'd FUN_01cd0ac0 (daemon) shows it calls
 * sce::np::User::GetUser(user_id, &out) which checks user_id against
 * sceUserServiceGetRegisteredUserIdList. uid=16 is in FS but not in registered
 * list → User::GetUser returns 0x80559e2a → daemon wraps to 0x80553917.
 *
 * Fix: patch User::GetUser (libSceNpManager offset 0x5b80) entry to:
 * mov [rsi+8], edi; out->user_id = user_id (= what success path does)
 * xor eax, eax; return 0 success
 * ret
 * = 6 bytes: 89 7E 08 31 C0 C3
 *
 * Effect: ANY user_id accepted by daemon. Combined with FS scan giving some
 * uid, CreateContext succeeds.
 *
 * Gated fw==10.01 only (9.40/7.61 don't need this because user IS signed in
 * properly when tester operates them).
 * ============================================================================ */
static constexpr uint8_t B13_GETUSER_PATCH[6] = {
    0x89, 0x7E, 0x08, /* mov [rsi+8], edi; out->user_id = user_id (arg1) */
    0x31, 0xC0, /* xor eax, eax; return 0 */
    0xC3 /* ret */
};

static int do_b13_user_getuser_patch(pid_t shellcore_pid) {
    const phu_fw_offsets_t *fw = phu_fw_offsets_current;
    /* r19.30 — extend to 8.00 (beta tester offact uid=171 hit 0x80553917 USER_NOT_FOUND).
     * r19.56 — extend to 10.00 (Cronos era launch fw, same strict User checks as 10.01).
     * libSceNpManager User symbols are stable cross-fw → safe to apply on any fw with offact users. */
    bool needs_user_bypass = fw && fw->fw_label &&
                              (strcmp(fw->fw_label, "10.00") == 0
                               || strcmp(fw->fw_label, "10.01") == 0
                               || strcmp(fw->fw_label, "8.00") == 0);
    if (!needs_user_bypass) {
        return 1; /* skip on fws where User::GetUser works with normal signed-in users */
    }

    uint32_t handle = 0;
    if (kernel_dynlib_handle(shellcore_pid, "libSceNpManager.sprx", &handle) != 0
        || handle == 0) {
        klog_printf("[trophy] B13 libSceNpManager handle FAIL in SceShellCore pid=%d\n",
                    shellcore_pid);
        phu_diag_log("trophy B13 libmgr handle fail");
        return 0;
    }

    /* Resolve sce::np::User::GetUser via mangled C++ symbol. */
    intptr_t getuser_va = kernel_dynlib_dlsym(shellcore_pid, handle,
                                               "_ZN3sce2np4User7GetUserEiPS1_");
    if (getuser_va == 0) {
        /* Fallback: try unmangled name. */
        getuser_va = kernel_dynlib_dlsym(shellcore_pid, handle, "GetUser");
    }
    if (getuser_va == 0) {
        klog_printf("[trophy] B13 dlsym User::GetUser FAIL\n");
        phu_diag_log("trophy B13 dlsym GetUser fail");
        return 0;
    }

    klog_printf("[trophy] B13 User::GetUser found @ 0x%lx (SceShellCore's libSceNpManager)\n",
                (uintptr_t)getuser_va);

    uint8_t pre[6] = {0};
    if (!prw::proc_read(shellcore_pid, getuser_va, pre, 6)) {
        klog_printf("[trophy] B13 read FAIL @ 0x%lx\n", (uintptr_t)getuser_va);
        phu_diag_log("trophy B13 read fail va=0x%lx", (uintptr_t)getuser_va);
        return 0;
    }
    klog_printf("[trophy] B13 pre: %02x %02x %02x %02x %02x %02x\n",
                pre[0], pre[1], pre[2], pre[3], pre[4], pre[5]);

    /* Already-patched detection */
    if (memcmp(pre, B13_GETUSER_PATCH, 6) == 0) {
        klog_printf("[trophy] B13 already patched — skip\n");
        return 1;
    }

    rollback_record(shellcore_pid, getuser_va, 6);
    if (!prw::proc_write(shellcore_pid, getuser_va, B13_GETUSER_PATCH, 6)) {
        klog_printf("[trophy] B13 write FAIL\n");
        phu_diag_log("trophy B13 write fail");
        return 0;
    }

    int mp = kernel_mprotect(shellcore_pid, (intptr_t)(getuser_va & ~0xFFFL), 0x1000,
                              PROT_READ | PROT_EXEC);
    if (mp != 0) {
        klog_printf("[trophy] B13 mprotect WARN ret=%d\n", mp);
    }

    uint8_t post[6] = {0};
    if (!prw::proc_read(shellcore_pid, getuser_va, post, 6)) {
        klog_printf("[trophy] B13 verify-read FAIL\n");
        return 0;
    }
    klog_printf("[trophy] B13 post: %02x %02x %02x %02x %02x %02x\n",
                post[0], post[1], post[2], post[3], post[4], post[5]);
    if (memcmp(post, B13_GETUSER_PATCH, 6) != 0) {
        klog_printf("[trophy] B13 verify MISMATCH\n");
        return 0;
    }

    klog_printf("[trophy] B13 User::GetUser patched OK — ANY user_id accepted by daemon\n");
    phu_diag_log("trophy B13 patched libSceNpManager:User::GetUser va=0x%lx",
                 (uintptr_t)getuser_va);
    return 1;
}

/* ============================================================================
 * B14 r19.19 — Patch sce::np::User::IsLoggedIn in libSceNpManager.
 *
 * Runtime diag r19.18: B13 made User::GetUser accept any user_id. Then
 * Context::InitForGame (FUN_01cc92c0, np_trophy2_context.cpp:0x53) calls
 * sce::np::User::IsLoggedIn which calls sceUserServiceIsLoggedIn(user_id).
 * Returns false on offact / non-signed-in users → InitForGame returns 0x80553918.
 *
 * Fix: patch User::IsLoggedIn to always return true.
 * mov al, 1; B0 01
 * ret; C3
 * = 3 bytes: B0 01 C3
 * ============================================================================ */
static constexpr uint8_t B14_ISLOGGEDIN_PATCH[3] = {
    0xB0, 0x01, /* mov al, 1 */
    0xC3 /* ret */
};

static int do_b14_isloggedin_patch(pid_t shellcore_pid) {
    const phu_fw_offsets_t *fw = phu_fw_offsets_current;
    /* r19.30 — extend to 8.00 (offact users).
     * r19.56 — extend to 10.00 (Cronos era launch fw, mirror 10.01). */
    bool needs_user_bypass = fw && fw->fw_label &&
                              (strcmp(fw->fw_label, "10.00") == 0
                               || strcmp(fw->fw_label, "10.01") == 0
                               || strcmp(fw->fw_label, "8.00") == 0);
    if (!needs_user_bypass) {
        return 1; /* skip on fws where IsLoggedIn returns true normally */
    }

    uint32_t handle = 0;
    if (kernel_dynlib_handle(shellcore_pid, "libSceNpManager.sprx", &handle) != 0
        || handle == 0) {
        klog_printf("[trophy] B14 libSceNpManager handle FAIL\n");
        return 0;
    }

    intptr_t va = kernel_dynlib_dlsym(shellcore_pid, handle,
                                       "_ZNK3sce2np4User10IsLoggedInEv");
    if (va == 0) {
        va = kernel_dynlib_dlsym(shellcore_pid, handle, "IsLoggedIn");
    }
    if (va == 0) {
        klog_printf("[trophy] B14 dlsym User::IsLoggedIn FAIL\n");
        return 0;
    }

    klog_printf("[trophy] B14 User::IsLoggedIn @ 0x%lx\n", (uintptr_t)va);

    uint8_t pre[3] = {0};
    if (!prw::proc_read(shellcore_pid, va, pre, 3)) {
        klog_printf("[trophy] B14 read FAIL\n");
        return 0;
    }
    if (memcmp(pre, B14_ISLOGGEDIN_PATCH, 3) == 0) {
        klog_printf("[trophy] B14 already patched — skip\n");
        return 1;
    }

    rollback_record(shellcore_pid, va, 3);
    if (!prw::proc_write(shellcore_pid, va, B14_ISLOGGEDIN_PATCH, 3)) {
        klog_printf("[trophy] B14 write FAIL\n");
        return 0;
    }
    kernel_mprotect(shellcore_pid, (intptr_t)(va & ~0xFFFL), 0x1000,
                    PROT_READ | PROT_EXEC);

    uint8_t post[3] = {0};
    prw::proc_read(shellcore_pid, va, post, 3);
    if (memcmp(post, B14_ISLOGGEDIN_PATCH, 3) != 0) {
        klog_printf("[trophy] B14 verify MISMATCH\n");
        return 0;
    }

    klog_printf("[trophy] B14 User::IsLoggedIn patched OK — always returns true\n");
    phu_diag_log("trophy B14 patched libSceNpManager:User::IsLoggedIn va=0x%lx",
                 (uintptr_t)va);
    return 1;
}

/* ============================================================================
 * B15 r19.20 — Patch sce::np::User::IsGuest in libSceNpManager (preemptive).
 *
 * After r19.19 B14 (IsLoggedIn → true), next anticipated blocker on offact
 * users: IsGuest check might return TRUE → some downstream guards refuse.
 * IsGuest calls sceUserServiceIsGuestUser(user_id). Offact users may be
 * tagged as guests on the system.
 *
 * Patch:
 * xor eax, eax; 31 C0
 * ret; C3
 * = 3 bytes: always returns FALSE = not a guest
 *
 * Same safe approach as B14. Gated fw==10.01 only.
 * ============================================================================ */
static constexpr uint8_t B15_ISGUEST_PATCH[3] = {
    0x31, 0xC0, /* xor eax, eax */
    0xC3 /* ret */
};

static int do_b15_isguest_patch(pid_t shellcore_pid) {
    const phu_fw_offsets_t *fw = phu_fw_offsets_current;
    /* r19.30 — extend to 8.00 (offact users).
     * r19.56 — extend to 10.00 (Cronos era launch fw, mirror 10.01). */
    bool needs_user_bypass = fw && fw->fw_label &&
                              (strcmp(fw->fw_label, "10.00") == 0
                               || strcmp(fw->fw_label, "10.01") == 0
                               || strcmp(fw->fw_label, "8.00") == 0);
    if (!needs_user_bypass) {
        return 1; /* skip on fws where IsGuest returns false normally */
    }

    uint32_t handle = 0;
    if (kernel_dynlib_handle(shellcore_pid, "libSceNpManager.sprx", &handle) != 0
        || handle == 0) {
        klog_printf("[trophy] B15 libSceNpManager handle FAIL\n");
        return 0;
    }

    intptr_t va = kernel_dynlib_dlsym(shellcore_pid, handle,
                                       "_ZNK3sce2np4User7IsGuestEv");
    if (va == 0) {
        va = kernel_dynlib_dlsym(shellcore_pid, handle, "IsGuest");
    }
    if (va == 0) {
        klog_printf("[trophy] B15 dlsym User::IsGuest FAIL\n");
        return 0;
    }

    klog_printf("[trophy] B15 User::IsGuest @ 0x%lx\n", (uintptr_t)va);

    uint8_t pre[3] = {0};
    if (!prw::proc_read(shellcore_pid, va, pre, 3)) {
        klog_printf("[trophy] B15 read FAIL\n");
        return 0;
    }
    if (memcmp(pre, B15_ISGUEST_PATCH, 3) == 0) {
        klog_printf("[trophy] B15 already patched — skip\n");
        return 1;
    }

    rollback_record(shellcore_pid, va, 3);
    if (!prw::proc_write(shellcore_pid, va, B15_ISGUEST_PATCH, 3)) {
        klog_printf("[trophy] B15 write FAIL\n");
        return 0;
    }
    kernel_mprotect(shellcore_pid, (intptr_t)(va & ~0xFFFL), 0x1000,
                    PROT_READ | PROT_EXEC);

    uint8_t post[3] = {0};
    prw::proc_read(shellcore_pid, va, post, 3);
    if (memcmp(post, B15_ISGUEST_PATCH, 3) != 0) {
        klog_printf("[trophy] B15 verify MISMATCH\n");
        return 0;
    }

    klog_printf("[trophy] B15 User::IsGuest patched OK — always returns FALSE\n");
    phu_diag_log("trophy B15 patched libSceNpManager:User::IsGuest va=0x%lx",
                 (uintptr_t)va);
    return 1;
}

/* ============================================================================
 * B16 r19.21 — Patch FUN_019e92f0 (user_status normalizer) in SceShellCore.
 *
 * RE'd FUN_019e92f0: calls get_authinfo, returns 0/1/0xffffffff based on
 * authinfo bit checks. Returns 1 = "regular logged-in user".
 *
 * 19+ trophy handlers check `FUN_019e92f0(user_status) == 1` → if != 1,
 * return 0x80553923 (= USER_NOT_LOGGED_IN_AT_NP_MANAGER level).
 *
 * Patch:
 * mov eax, 1; B8 01 00 00 00
 * ret; C3
 * = 6 bytes
 *
 * Effect: ALL `user_status == 1` checks pass regardless of authinfo state.
 * Bypasses 19+ sites of 0x80553923 in trophy chain.
 *
 * 10.01 VA = 0x019e92f0. Gated fw==10.01.
 * ============================================================================ */
static constexpr uint8_t B16_USER_STATUS_PATCH[6] = {
    0xB8, 0x01, 0x00, 0x00, 0x00, /* mov eax, 1 */
    0xC3 /* ret */
};

/* B16 user_status site (10.01).
 * Pre-fix it was a hardcoded plaintext 0x019e92f0UL grep-able in.text.
 * Stored as a single static uint64_t in this public source release. */
static const uint64_t B16_USER_STATUS_VA = 0x019e92f0UL;

static int do_b16_user_status_patch(pid_t shellcore_pid, uintptr_t shellcore_base,
                                    uintptr_t image_base) {
    /* r19.58 — B16 retired (was 10.01-only band-aid on B3 cascade, not needed
     * since B3 is disabled-by-design on Cronos. 10.00 works clean without it). */
    (void)shellcore_pid; (void)shellcore_base; (void)image_base;
    return 1;
    const phu_fw_offsets_t *fw = phu_fw_offsets_current;
    if (!fw || !fw->fw_label || strcmp(fw->fw_label, "10.01") != 0) {
        return 1;
    }

    uintptr_t va = shellcore_base + (B16_USER_STATUS_VA - image_base);

    uint8_t pre[6] = {0};
    if (!prw::proc_read(shellcore_pid, va, pre, 6)) {
        klog_printf("[trophy] B16 read FAIL @ 0x%lx\n", va);
        return 0;
    }
    if (memcmp(pre, B16_USER_STATUS_PATCH, 6) == 0) {
        klog_printf("[trophy] B16 already patched — skip\n");
        return 1;
    }

    rollback_record(shellcore_pid, va, 6);
    if (!prw::proc_write(shellcore_pid, va, B16_USER_STATUS_PATCH, 6)) {
        klog_printf("[trophy] B16 write FAIL\n");
        return 0;
    }
    kernel_mprotect(shellcore_pid, (intptr_t)(va & ~0xFFFL), 0x1000,
                    PROT_READ | PROT_EXEC);

    uint8_t post[6] = {0};
    prw::proc_read(shellcore_pid, va, post, 6);
    if (memcmp(post, B16_USER_STATUS_PATCH, 6) != 0) {
        klog_printf("[trophy] B16 verify MISMATCH\n");
        return 0;
    }

    klog_printf("[trophy] B16 FUN_019e92f0 patched OK — user_status always returns 1\n");
    phu_diag_log("trophy B16 patched FUN_019e92f0 va=0x%lx (user_status=1)", va);
    return 1;
}

/* ============================================================================
 * B17 r19.22 — Patch 4 sites of MOV R15D, 0x8055391e in FUN_01ccdd40 (SceShellCore).
 *
 * After r19.21 user state fully bypassed, RegisterContext now fails with
 * 0x8055391e from FUN_01ccdd40 (IpcJob Phase 5 helper that builds BindInfo
 * via 16-slot service label loop). Empty BindInfoSet (B10 nuke side-effect)
 * → all 4 fail paths set R15D = 0x8055391e.
 *
 * Patch each `MOV R15D, 0x8055391e` (= 6 bytes: 41 BF 1E 39 55 80) to
 * `XOR R15D, R15D` + 3 NOPs (= 6 bytes: 45 31 FF 90 90 90).
 *
 * Sites (10.01 SceShellCore image_base 0x01000000):
 * 0x01ccdee0 (vtable+0x18 returned 0x8055391e)
 * 0x01cce008 (FUN_01ce9a10 returned < 0, NOT 0x8055390c)
 * 0x01cce014 (loop completed 16 iters without match)
 * 0x01cce02a (BindInfoSet local_60 == NULL after FUN_01ce9a10)
 *
 * Effect: function returns 0 (R15D=0) in all fail paths instead of 0x8055391e.
 * Risk: caller may use unpopulated param_6, but most likely it checks
 * function return code first.
 * ============================================================================ */
static constexpr uint8_t B17_ORIG_MOV_R15D_391E[6] = { 0x41, 0xBF, 0x1E, 0x39, 0x55, 0x80 };
static constexpr uint8_t B17_PATCH_XOR_R15D[6] = { 0x45, 0x31, 0xFF, 0x90, 0x90, 0x90 };

/* B17 sites (10.01).
 * Pre-fix these were plaintext literals readable via `strings phu_overlay.elf`.
 * Plain uint64_t array in this public source release. */
static const uint64_t B17_SITES_10_01[4] = {
    0x01ccdee0UL,
    0x01cce008UL,
    0x01cce014UL,
    0x01cce02aUL,
};
static int do_b17_register_391e_patch(pid_t shellcore_pid, uintptr_t shellcore_base,
                                       uintptr_t image_base) {
    /* r19.58 — B17 retired (was 10.01-only band-aid on B3 cascade, not needed
     * since B3 is disabled-by-design on Cronos. 10.00 works clean without it). */
    (void)shellcore_pid; (void)shellcore_base; (void)image_base;
    return 1;
    const phu_fw_offsets_t *fw = phu_fw_offsets_current;
    if (!fw || !fw->fw_label || strcmp(fw->fw_label, "10.01") != 0) {
        return 1;
    }

    int patched = 0;
    for (int i = 0; i < 4; i++) {
        uintptr_t site_va = B17_SITES_10_01[i];
        uintptr_t va = shellcore_base + (site_va - image_base);
        uint8_t pre[6] = {0};
        if (!prw::proc_read(shellcore_pid, va, pre, 6)) {
            klog_printf("[trophy] B17 site %d read FAIL @ 0x%lx\n", i, va);
            continue;
        }
        if (memcmp(pre, B17_PATCH_XOR_R15D, 6) == 0) {
            klog_printf("[trophy] B17 site %d already patched\n", i);
            patched++;
            continue;
        }
        if (memcmp(pre, B17_ORIG_MOV_R15D_391E, 6) != 0) {
            klog_printf("[trophy] B17 site %d unexpected bytes %02x %02x %02x %02x %02x %02x\n",
                        i, pre[0], pre[1], pre[2], pre[3], pre[4], pre[5]);
            continue;
        }

        rollback_record(shellcore_pid, va, 6);
        if (!prw::proc_write(shellcore_pid, va, B17_PATCH_XOR_R15D, 6)) {
            klog_printf("[trophy] B17 site %d write FAIL\n", i);
            continue;
        }
        kernel_mprotect(shellcore_pid, (intptr_t)(va & ~0xFFFL), 0x1000,
                        PROT_READ | PROT_EXEC);
        klog_printf("[trophy] B17 site %d patched @ 0x%lx\n", i, va);
        patched++;
    }

    klog_printf("[trophy] B17 FUN_01ccdd40 0x8055391e bypass: %d/4 sites patched\n", patched);
    phu_diag_log("trophy B17 391e-bypass: %d/4 sites", patched);
    return (patched > 0) ? 1: 0;
}

/* ============================================================================
 * B18 r19.23 — Force first-time path in FUN_01a6fcc0 (SceShellCore).
 *
 * RE 2026-05-14 mapped the complete IPMI cmd 0x90016 RegisterContext
 * chain on 10.01:
 *
 * Client (phu_trophy B6)
 * ↓ IPMI cmd 0x90016
 * libSceIpmi (transport, no 0x8055391e anywhere)
 * ↓
 * SceShellCore FUN_01cd4e90 (sync IPMI handler)
 * ├─ checks B16 user_status, param validity → all OK
 * └─ submits async RegisterContextIpcJob (ctor FUN_01cd50f0)
 * ↓ async execution
 * FUN_01a6f610 (mask wrapper) → FUN_01a709e0 → FUN_01a6fcc0 (orchestrator)
 * ↓
 * FUN_01a6fcc0 branches on state byte cVar1 @ context+0x3d:
 * ├─ cVar1 == 0 → FIRST-TIME PATH (FUN_01ccbc00 → FUN_01ccdd40 →
 * │ FUN_01ccc1b0 → FUN_01ccc3d0). At end @ 0x01a7037b:
 * │ CMP R12D, 0x8055391e
 * │ CMOVNZ EAX, R12D ← SWALLOWS 0x8055391e → return 0
 * │
 * └─ cVar1 != 0 → ELSE PATH (shorter chain, FUN_01ccdd40 → FUN_01ccc1b0).
 * NO SWALLOW → 0x8055391e leaks to client.
 *
 * On 10.01, beta tester runtime shows rc=0x8055391e despite B17 patching all
 * 4 MOV sites in FUN_01ccdd40. Reason: the actual source is the vtable+0x18
 * call return inside the 16-iter loop, not a MOV. B17 cannot fix.
 *
 * B18 surgical 3-byte patch @ 0x01a6fd0a:
 * Pre: 45 84 E4 TEST R12B, R12B (test state byte)
 * Post: 45 30 E4 XOR R12B, R12B (zero R12B, set ZF=1)
 *
 * Effect: ZF=1 always → JZ @ 0x01a6fd0d always taken → first-time path forced
 * → 0x8055391e swallowed by CMOVNZ → return 0 success.
 *
 * Safety:
 * - R12 is callee-saved in System V AMD64 ABI → safe to clobber here
 * - R12D is reloaded inside both paths (@ 0x01a6fdfa else, 0x01a70049 first)
 * so the XOR does not corrupt any downstream value
 * - 3-byte patch (no NOP padding needed) — minimal disturbance
 * - Per-fw gate: 9.40/7.61 have b18_force_firsttime_va=0 → no patch applied
 *
 * Trade-off: forces re-init even if context was already initialized. For the
 * use case (1 trophy install per game), this is fine. If Sony's chain detects
 * dup ctx, FUN_01ccbc00 returns 0x8055390c (not 0x8055391e) → propagated, and
 * would see that in next beta diag.
 * ============================================================================ */
static constexpr uint8_t B18_ORIG_TEST_R12B[3] = { 0x45, 0x84, 0xE4 }; /* TEST R12B, R12B */
static constexpr uint8_t B18_PATCH_XOR_R12B[3] = { 0x45, 0x30, 0xE4 }; /* XOR R12B, R12B */

static int do_b18_force_firsttime_path(pid_t shellcore_pid, uintptr_t shellcore_base,
                                        uintptr_t image_base) {
    const phu_trophy_fw_offsets_t *e = get_fw_offsets;
    if (!e) return 0;
    if (e->b18_force_firsttime_va == 0) {
        klog_printf("[trophy] B18 skip: fw '%s' does not need force-first-time\n",
                    e->fw_label ? e->fw_label: "?");
        return 1; /* not-needed = success */
    }

    uintptr_t va = shellcore_base + (e->b18_force_firsttime_va - image_base);
    uint8_t pre[3] = {0};
    uint8_t post[3] = {0};

    if (!prw::proc_read(shellcore_pid, va, pre, sizeof(pre))) {
        klog_printf("[trophy] B18 read FAIL (va=0x%lx)\n", va);
        phu_diag_log("trophy B18 read FAIL va=0x%lx", va);
        return 0;
    }
    klog_printf("[trophy] B18 pre: %02x %02x %02x (expected 45 84 E4 = TEST R12B,R12B)\n",
                pre[0], pre[1], pre[2]);

    /* Already-patched detection (idempotent re-runs) */
    if (memcmp(pre, B18_PATCH_XOR_R12B, sizeof(B18_PATCH_XOR_R12B)) == 0) {
        klog_printf("[trophy] B18 already patched (va=0x%lx) — skip\n", va);
        phu_diag_log("trophy B18 already patched");
        return 1;
    }
    /* Strict pre-bytes check (don't break console if disassembly drifted) */
    if (memcmp(pre, B18_ORIG_TEST_R12B, sizeof(B18_ORIG_TEST_R12B)) != 0) {
        klog_printf("[trophy] B18 unexpected pre bytes %02x %02x %02x "
                    "(expected 45 84 E4 = TEST R12B,R12B) — abort\n",
                    pre[0], pre[1], pre[2]);
        phu_diag_log("trophy B18 pre-mismatch %02x%02x%02x", pre[0], pre[1], pre[2]);
        return 0;
    }

    rollback_record(shellcore_pid, va, sizeof(B18_PATCH_XOR_R12B));
    if (!prw::proc_write(shellcore_pid, va,
                         B18_PATCH_XOR_R12B, sizeof(B18_PATCH_XOR_R12B))) {
        klog_printf("[trophy] B18 write FAIL (va=0x%lx)\n", va);
        phu_diag_log("trophy B18 write FAIL va=0x%lx", va);
        return 0;
    }

    /* TLB+µop cache flush */
    int mp = kernel_mprotect(shellcore_pid, (intptr_t)(va & ~0xFFFUL), 0x1000,
                              PROT_READ | PROT_EXEC);
    if (mp != 0) {
        klog_printf("[trophy] B18 mprotect WARN ret=%d\n", mp);
    }

    if (!prw::proc_read(shellcore_pid, va, post, sizeof(post))) {
        klog_printf("[trophy] B18 verify-read FAIL\n");
        return 0;
    }
    klog_printf("[trophy] B18 post: %02x %02x %02x\n", post[0], post[1], post[2]);
    if (memcmp(post, B18_PATCH_XOR_R12B, sizeof(B18_PATCH_XOR_R12B)) != 0) {
        klog_printf("[trophy] B18 verify MISMATCH @ va=0x%lx\n", va);
        return 0;
    }

    klog_printf("[trophy] B18 patched: va=0x%lx FUN_01a6fcc0 TEST→XOR R12B "
                "(force first-time path, swallow 0x8055391e) OK\n", va);
    phu_diag_log("trophy B18 force-firsttime va=0x%lx (swallow 0x8055391e)", va);
    return 1;
}

/* B1+B3+B4+B5_LNC done flags — set when init_boot completes all patches,
 * checked by apply_per_game to refuse B2+B6 on partial daemon state (avoids
 * panic from half-defeated commid gate or LNC misfire). Re-set by
 * check_persistence after SceShellCore restart-driven full re-patch. */
static bool g_b1_full_done = false;
static bool g_b3_full_done = false;
static bool g_b4_full_done = false;
static bool g_b5_lnc_full_done = false;

/* r19.32 — lazy_init flag: tracks whether SceShellCore patches were applied
 * during current session. Set by apply_per_game on first PS5 native game.
 * Cleared by phu_trophy_rollback_boot at game-vanish so next session starts
 * fresh. File-scope (not static-in-function) so rollback can reset it. */
static bool g_trophy_lazy_init_done = false;

/* r19.32 — Rollback registry: stores original SceShellCore bytes BEFORE each
 * patch is applied. phu_trophy_rollback_boot iterates this on game-vanish
 * to restore vanilla state so PS4 BC games can launch cleanly afterwards.
 *
 * Capacity: 32 sites × 16 bytes each = 512 bytes data. Current patch count:
 * B1 (4 slots) + B3 (2 slots) + B4 (1) + B5_LNC (1) + B13/14/15 (3) = ~11 sites
 * Headroom for future patches without recompile-time growth. */
struct phu_trophy_rollback_site_t {
    uintptr_t va; /* SceShellCore VA (absolute, includes base) */
    uint16_t size; /* 1..16 bytes */
    uint8_t bytes[16]; /* original pre-patch bytes */
};
/* r19.56 hotfix-3 H-5: bumped capacity 32→64 to accommodate Phase B rollback
 * extension for B8-B18 (~25 additional sites possible on 10.01 Cronos). */
static phu_trophy_rollback_site_t g_rollback_sites[64];
static int g_rollback_count = 0;
static bool g_rollback_full = false; /* set on overflow / read fail */
static pid_t g_rollback_shellcore_pid = -1;
static uintptr_t g_rollback_shellcore_base = 0;

/* Record SceShellCore pre-patch bytes at va for rollback. Called by each
 * do_*_patch function right BEFORE its prw::proc_write. Idempotent: if the
 * VA is already in the registry, don't overwrite (preserves the EARLIEST
 * saved bytes which are guaranteed-original — re-apply via persistence sees
 * patched bytes and would corrupt the registry). */
static void rollback_record(pid_t shellcore_pid, uintptr_t va, size_t size) {
    if (size == 0 || size > sizeof(g_rollback_sites[0].bytes)) {
        klog_printf("[trophy] rollback_record: bad size=%zu @ va=0x%lx\n", size, va);
        g_rollback_full = true;
        return;
    }
    /* Idempotent: skip if VA already saved (persistence re-apply path). */
    for (int i = 0; i < g_rollback_count; i++) {
        if (g_rollback_sites[i].va == va) return;
    }
    if (g_rollback_count >= (int)(sizeof(g_rollback_sites) / sizeof(g_rollback_sites[0]))) {
        klog_printf("[trophy] rollback_record: registry FULL — refusing va=0x%lx\n", va);
        g_rollback_full = true;
        return;
    }
    auto &slot = g_rollback_sites[g_rollback_count];
    slot.va = va;
    slot.size = (uint16_t)size;
    if (!prw::proc_read(shellcore_pid, va, slot.bytes, size)) {
        klog_printf("[trophy] rollback_record: READ FAIL @ va=0x%lx size=%zu\n", va, size);
        g_rollback_full = true;
        return;
    }
    g_rollback_shellcore_pid = shellcore_pid;
    g_rollback_count++;
}

/* Forward declarations — B7 file copy is defined below apply_per_game. */
static int phu_trophy_setup_appmeta(const char *titleid);
static int b6_diag_check_npbind(const char *titleid);
static int b7_extract_npwr_from_npbind(const char *titleid, char out_npwr[16]);
static bool phu_trophy_already_installed(const char *titleid);
/* r19.60 — post-install disk state dump, helps RE "trophies don't appear in
 * profile" bugs without needing a klog stream. Defined below b7 helpers. */
static void do_post_install_diag(int game_pid, const char *titleid, int b6_rc);
/* r19.61 — per-user already-installed check.
 * Inspects /user/home/<uid_hex>/trophy2/nobackup/data/<NPWR>/TRPTITLE.DAT
 * (PS5 native) or /user/home/<uid_hex>/trophy/data/<NPWR>/trophy.img (PS4 BC).
 * Returns true if the SPECIFIC PSN user already has this NPWR registered.
 * Fixes both multi-user isolation + historical trophy preservation (save-
 * triggered unlocks need natural Sony chain, not the B2 fake-secret inject).
 * Defined below b7 helpers. */
static bool phu_trophy_already_installed_for_user(const char *titleid, int uid);

/* PS5 native titleid check (PPSA / PPSB prefix). Trophy bypass is needed only
 * for raw PS5 dumps: PS4 BC games come from fpkg installs (Sony installer ran)
 * → trophies already work natively via Trophy 1 path. Skip them entirely to
 * avoid wasteful re-runs of B7 + B6 on every launch. */
static inline bool trophy_is_ps5_native(const char *titleid) {
    if (!titleid || !titleid[0] || !titleid[1] || !titleid[2] || !titleid[3]) {
        return false;
    }
    bool pps = (titleid[0] == 'P' || titleid[0] == 'p') &&
               (titleid[1] == 'P' || titleid[1] == 'p') &&
               (titleid[2] == 'S' || titleid[2] == 's');
    if (!pps) return false;
    char c = titleid[3];
    return (c == 'A' || c == 'a' || c == 'B' || c == 'b');
}

/* B6 once-per-titleid gate. apply_per_game fires on every game-detect cycle;
 * trophy install only needs to happen ONCE per session. Repeat calls would
 * either no-op (already-registered) or spam the user with "install OK" toast. */
static char g_b6_done_titleid[16] = {0};

/* r19.57 — Smart fast-path cache was prototyped but reverted.
 * Reason: within a single game session apply_per_game fires only once (at
 * game-detect). Across cycles rollback_boot removes SceShellCore patches, so
 * a cache hit would skip patches that the game's natural register needs (on
 * 4.03/6.02/Cronos). The ~500ms full-chain cost per launch is idempotent and
 * negligible compared to game launch time. */

/* ============================================================================
 * r19.10 — 10.01 DIAGNOSTIC: DMAP-read trophy daemon singletons
 * ----------------------------------------------------------------------------
 * RE session 2026-05-14 revealed that on 10.01:
 * - IPMI cmd 0x90016 RegisterContext routes via IpcJob (Path B), NOT
 * Path A worker (FUN_01d6f7b0). Sony replaced direct handler with async
 * dispatch.
 * - Phase 2 of IpcJob calls FUN_01a8f9a0 RegisterContextInUlms which checks
 * DAT_02f52010 (SceNpBindLocal handle) + DAT_03045940 (Ulms client factory).
 * - Runtime fails rc=0x8055d205 = these singletons are NULL on 10.01.
 * - Init code exists (FUN_01a8f810 sceNpBindLocalVshInit + FUN_01d7f1e0
 * sceNpUlmsInit, both called from FUN_01af0580 sceNpVshInit at SceShellCore
 * boot) — but may have failed silently or been skipped.
 *
 * This function DMAP-reads the singleton state on PHU boot and logs everything.
 * Output drives r19.11 strategy choice:
 * - All NULL → singletons never initialized → call init manually (Strategy F)
 * - Some NULL → partial init → only init missing ones
 * - All non-NULL → singletons OK, bug elsewhere → audit Phase 2 chain further
 *
 * Gated to fw==10.01 only (other fws don't have these DAT addresses verified).
 * Reads 8 singletons + 6-byte init flags bitmap. All logged to phu-klog +
 * PHUdiag.txt for offline review.
 *
 * Addresses (image_base 0x01000000):
 * DAT_02f52010 = SceNpBindLocal IPC client handle (qword)
 * DAT_03045940 = NpUlms client factory (qword)
 * DAT_03044270 = TrophyDaemonService singleton (qword)
 * DAT_03044288 = Trophy2UlmsManager singleton (qword)
 * DAT_02f51f88 = HorizonMediator singleton (qword)
 * DAT_03044208 = Trophy2 init flag (byte, set after sceNpTrophy2VshInit)
 * DAT_030442e0 = TrophyV1 init flag (byte, set after sceNpTrophyVshInit)
 * DAT_02f52168 = NP init flags bitmap (6 bytes, each step in sceNpVshInit)
 * ============================================================================ */
static void phu_trophy_diag_10_01(pid_t shellcore_pid, uintptr_t shellcore_base,
                                  uintptr_t image_base) {
    const phu_fw_offsets_t *fw = phu_fw_offsets_current;
    if (!fw || !fw->fw_label || strcmp(fw->fw_label, "10.01") != 0) {
        return; /* fw guard — only 10.01 has these DAT addresses verified */
    }

    /* Reusable VA computer: runtime = base + (static_va - image_base). */
    auto va_at = [&](uintptr_t static_va) -> uintptr_t {
        return shellcore_base + (static_va - image_base);
    };

    /* Read all 5 qword singletons + 2 init flag bytes + 6-byte bitmap. */
    uint64_t bindlocal = 0, ulms = 0, t2_svc = 0, t2_ulms_mgr = 0, horizon = 0;
    uint8_t t2_init = 0, v1_init = 0, init_flags[6] = {0};

    bool ok_bl = prw::proc_read(shellcore_pid, va_at(0x02f52010UL), &bindlocal, sizeof(bindlocal));
    bool ok_ul = prw::proc_read(shellcore_pid, va_at(0x03045940UL), &ulms, sizeof(ulms));
    bool ok_t2s = prw::proc_read(shellcore_pid, va_at(0x03044270UL), &t2_svc, sizeof(t2_svc));
    bool ok_t2m = prw::proc_read(shellcore_pid, va_at(0x03044288UL), &t2_ulms_mgr, sizeof(t2_ulms_mgr));
    bool ok_hor = prw::proc_read(shellcore_pid, va_at(0x02f51f88UL), &horizon, sizeof(horizon));
    bool ok_t2i = prw::proc_read(shellcore_pid, va_at(0x03044208UL), &t2_init, 1);
    bool ok_v1i = prw::proc_read(shellcore_pid, va_at(0x030442e0UL), &v1_init, 1);
    bool ok_fl = prw::proc_read(shellcore_pid, va_at(0x02f52168UL), init_flags, 6);

    /* Log to klog (mirror to phu-klog automatically). */
    klog_printf("[trophy-10.01-diag] === SINGLETON STATE DUMP ===\n");
    klog_printf("[trophy-10.01-diag] SceShellCore: pid=%d base=0x%lx image_base=0x%lx\n",
                shellcore_pid, shellcore_base, image_base);
    klog_printf("[trophy-10.01-diag] DAT_02f52010 (SceNpBindLocal handle) = 0x%016lx %s\n",
                bindlocal, ok_bl ? (bindlocal ? "READY": "NULL → blocks FUN_01a8f9a0!"): "READ-FAIL");
    klog_printf("[trophy-10.01-diag] DAT_03045940 (NpUlms factory) = 0x%016lx %s\n",
                ulms, ok_ul ? (ulms ? "READY": "NULL → blocks FUN_01a8f9a0!"): "READ-FAIL");
    klog_printf("[trophy-10.01-diag] DAT_03044270 (TrophyDaemonService) = 0x%016lx %s\n",
                t2_svc, ok_t2s ? (t2_svc ? "READY": "NULL → blocks IpcJob"): "READ-FAIL");
    klog_printf("[trophy-10.01-diag] DAT_03044288 (Trophy2UlmsManager) = 0x%016lx %s\n",
                t2_ulms_mgr, ok_t2m ? (t2_ulms_mgr ? "READY": "NULL → blocks ULMS"): "READ-FAIL");
    klog_printf("[trophy-10.01-diag] DAT_02f51f88 (HorizonMediator) = 0x%016lx %s\n",
                horizon, ok_hor ? (horizon ? "READY": "NULL → blocks P4"): "READ-FAIL");
    klog_printf("[trophy-10.01-diag] DAT_03044208 (Trophy2 init flag byte) = 0x%02x %s\n",
                t2_init, ok_t2i ? (t2_init ? "DONE": "NOT-INIT → sceNpTrophy2VshInit skipped"): "READ-FAIL");
    klog_printf("[trophy-10.01-diag] DAT_030442e0 (TrophyV1 init flag) = 0x%02x %s\n",
                v1_init, ok_v1i ? (v1_init ? "DONE": "NOT-INIT → sceNpTrophyVshInit skipped"): "READ-FAIL");
    if (ok_fl) {
        klog_printf("[trophy-10.01-diag] DAT_02f52168 (NP init flags bitmap) = "
                    "%02x %02x %02x %02x %02x %02x\n",
                    init_flags[0], init_flags[1], init_flags[2],
                    init_flags[3], init_flags[4], init_flags[5]);
        klog_printf("[trophy-10.01-diag] byte[5] bit 0x04 = UlmsInit: %s\n",
                    (init_flags[5] & 0x04) ? "DONE": "MISSING");
        klog_printf("[trophy-10.01-diag] byte[5] bit 0x08 = BindLocalVshInit: %s\n",
                    (init_flags[5] & 0x08) ? "DONE": "MISSING");
        klog_printf("[trophy-10.01-diag] byte[4] bit 0x01 = Trophy2VshInit: %s\n",
                    (init_flags[4] & 0x01) ? "DONE": "MISSING");
        klog_printf("[trophy-10.01-diag] byte[1] bit 0x80 = TrophyVshInit: %s\n",
                    (init_flags[1] & 0x80) ? "DONE": "MISSING");
    } else {
        klog_printf("[trophy-10.01-diag] DAT_02f52168 read FAILED\n");
    }
    klog_printf("[trophy-10.01-diag] === END DUMP ===\n");

    /* PHUdiag summary line (single line for compact offline review). */
    phu_diag_log("trophy-10.01-diag BL=%lx Ulms=%lx T2svc=%lx T2mgr=%lx "
                 "Hor=%lx T2flag=%x V1flag=%x flags=%02x%02x%02x%02x%02x%02x",
                 bindlocal, ulms, t2_svc, t2_ulms_mgr, horizon,
                 t2_init, v1_init,
                 init_flags[0], init_flags[1], init_flags[2],
                 init_flags[3], init_flags[4], init_flags[5]);

    /* Read FUN_01d1c230 (= use_trophy2_path feature flag function) bytes at
     * entry. If Sony has defaulted it to "mov al,1; ret" (b0 01 c3) on 10.01,
     * that proves IpcJob is the default routing → confirms the finding that
     * Path A worker is dead code on 10.01.
     * Expected on 7.61/9.40: different prologue (returns 0 by default).
     * Expected on 10.01: possibly b0 01 c3 already (Sony enabled by default). */
    uint8_t flag_func_prologue[6] = {0};
    if (prw::proc_read(shellcore_pid, va_at(0x01d1c230UL), flag_func_prologue, 6)) {
        klog_printf("[trophy-10.01-diag] FUN_01d1c230 prologue (use_trophy2_path) = "
                    "%02x %02x %02x %02x %02x %02x %s\n",
                    flag_func_prologue[0], flag_func_prologue[1], flag_func_prologue[2],
                    flag_func_prologue[3], flag_func_prologue[4], flag_func_prologue[5],
                    (flag_func_prologue[0] == 0xb0 && flag_func_prologue[1] == 0x01)
                        ? "→ DEFAULTED TRUE (IpcJob forced — Path B routing always)"
: "→ original (returns variable)");
    }

    /* Quick verdict log for at-a-glance triage. */
    int null_count = (bindlocal==0) + (ulms==0) + (t2_svc==0) + (t2_ulms_mgr==0) + (horizon==0);
    klog_printf("[trophy-10.01-diag] VERDICT: %d/5 critical singletons NULL; "
                "T2init=%d V1init=%d → ",
                null_count, t2_init, v1_init);
    if (null_count == 0 && t2_init && v1_init) {
        klog_printf("ALL READY (bug elsewhere; audit Phase 2 deeper OR IPMI routes Path B by default)\n");
    } else if (bindlocal == 0 && ulms == 0) {
        klog_printf("STRATEGY F = pt_call sceNpUlmsInit + sceNpBindLocalVshInit manually\n");
    } else if (bindlocal == 0) {
        klog_printf("STRATEGY F = pt_call sceNpBindLocalVshInit only (Ulms already up)\n");
    } else {
        klog_printf("PARTIAL INIT — needs per-singleton analysis (check phu-klog)\n");
    }
}

/* ============================================================================
 * r19.39 B20 — IsDeprecatedVersion bypass (FUN_01a9f010 on 4.03)
 * ----------------------------------------------------------------------------
 * 3-byte patch overwriting function entry with `31 C0 C3` (XOR EAX,EAX; RET)
 * → function returns FALSE always (= "not deprecated").
 * Original entry: 55 48 89 e5 53 50... (standard C++ prologue).
 * Skip-if-zero: only fws with this Sony bug have non-zero VA in their row.
 * ============================================================================ */
static constexpr uint8_t B20_PATCH_XOR_RET[3] = { 0x31, 0xC0, 0xC3 }; /* XOR EAX,EAX; RET */

static int do_b20_isdeprecated_bypass_patch(pid_t shellcore_pid, uintptr_t shellcore_base,
                                             uintptr_t image_base) {
    const phu_trophy_fw_offsets_t *e = get_fw_offsets;
    if (!e || e->b20_isdeprecated_va == 0) {
        return 1; /* skip-if-zero — fw doesn't need this patch (Sony fixed in later fws) */
    }

    uintptr_t va = shellcore_base + (e->b20_isdeprecated_va - image_base);
    uint8_t pre[3] = {0};
    uint8_t post[3] = {0};

    if (!prw::proc_read(shellcore_pid, va, pre, 3)) {
        klog_printf("[trophy] B20 read FAIL (va=0x%lx)\n", va);
        phu_diag_log("trophy B20 read FAIL va=0x%lx", va);
        return 0;
    }

    /* Already-patched detection (idempotent) */
    if (memcmp(pre, B20_PATCH_XOR_RET, 3) == 0) {
        klog_printf("[trophy] B20 already patched (va=0x%lx) — skip\n", va);
        phu_diag_log("trophy B20 already patched");
        return 1;
    }

    /* Expected standard prologue: 55 48 89 (push rbp; mov rbp,...) */
    if (pre[0] != 0x55 || pre[1] != 0x48 || pre[2] != 0x89) {
        klog_printf("[trophy] B20 unexpected prologue %02x %02x %02x (va=0x%lx) — abort\n",
                    pre[0], pre[1], pre[2], va);
        phu_diag_log("trophy B20 pre-mismatch %02x%02x%02x", pre[0], pre[1], pre[2]);
        return 0;
    }

    /* Snapshot pre-patch bytes for rollback at game-vanish */
    rollback_record(shellcore_pid, va, 3);

    if (!prw::proc_write(shellcore_pid, va, B20_PATCH_XOR_RET, 3)) {
        klog_printf("[trophy] B20 write FAIL (va=0x%lx)\n", va);
        phu_diag_log("trophy B20 write FAIL");
        return 0;
    }
    kernel_mprotect(shellcore_pid, (intptr_t)(va & ~0xFFFUL), 0x1000,
                    PROT_READ | PROT_EXEC);

    if (!prw::proc_read(shellcore_pid, va, post, 3)) {
        klog_printf("[trophy] B20 verify-read FAIL\n");
        return 0;
    }
    if (memcmp(post, B20_PATCH_XOR_RET, 3) != 0) {
        klog_printf("[trophy] B20 verify MISMATCH @ va=0x%lx\n", va);
        phu_diag_log("trophy B20 verify MISMATCH");
        return 0;
    }

    klog_printf("[trophy] B20 IsDeprecatedVersion bypass patched @ 0x%lx "
                "(= always returns FALSE → UpdateSummaryFile gate fires WRITE path)\n", va);
    phu_diag_log("trophy B20 patched va=0x%lx", va);
    return 1;
}

/* ============================================================================
 * r19.39 B21 — RecoveryRequired setter disable (FUN_01aa0150 on 4.03)
 * ----------------------------------------------------------------------------
 * 3-byte patch overwriting function entry with `31 C0 C3` (XOR EAX,EAX; RET)
 * → function returns 0 (success) without executing the OR-bit-0 instruction.
 * Effect: new NPWR entries get no RecoveryRequired flag set → UpdateSummaryFile
 * gate's first condition (local_a1) stays 0 → WRITE path fires normally.
 * Original entry: 55 48 89 e5 41 57 41 56 53 48 (PUSH RBP/MOV/PUSH R15/PUSH R14/PUSH RBX).
 * Skip-if-zero pattern same as B20.
 * ============================================================================ */
static int do_b21_recovery_setter_disable_patch(pid_t shellcore_pid, uintptr_t shellcore_base,
                                                 uintptr_t image_base) {
    const phu_trophy_fw_offsets_t *e = get_fw_offsets;
    if (!e || e->b21_recovery_setter_va == 0) {
        return 1; /* skip-if-zero */
    }

    uintptr_t va = shellcore_base + (e->b21_recovery_setter_va - image_base);
    uint8_t pre[3] = {0};
    uint8_t post[3] = {0};

    if (!prw::proc_read(shellcore_pid, va, pre, 3)) {
        klog_printf("[trophy] B21 read FAIL (va=0x%lx)\n", va);
        phu_diag_log("trophy B21 read FAIL va=0x%lx", va);
        return 0;
    }

    if (memcmp(pre, B20_PATCH_XOR_RET, 3) == 0) {
        klog_printf("[trophy] B21 already patched (va=0x%lx) — skip\n", va);
        phu_diag_log("trophy B21 already patched");
        return 1;
    }

    if (pre[0] != 0x55 || pre[1] != 0x48 || pre[2] != 0x89) {
        klog_printf("[trophy] B21 unexpected prologue %02x %02x %02x (va=0x%lx) — abort\n",
                    pre[0], pre[1], pre[2], va);
        phu_diag_log("trophy B21 pre-mismatch %02x%02x%02x", pre[0], pre[1], pre[2]);
        return 0;
    }

    rollback_record(shellcore_pid, va, 3);

    if (!prw::proc_write(shellcore_pid, va, B20_PATCH_XOR_RET, 3)) {
        klog_printf("[trophy] B21 write FAIL (va=0x%lx)\n", va);
        phu_diag_log("trophy B21 write FAIL");
        return 0;
    }
    kernel_mprotect(shellcore_pid, (intptr_t)(va & ~0xFFFUL), 0x1000,
                    PROT_READ | PROT_EXEC);

    if (!prw::proc_read(shellcore_pid, va, post, 3)) {
        klog_printf("[trophy] B21 verify-read FAIL\n");
        return 0;
    }
    if (memcmp(post, B20_PATCH_XOR_RET, 3) != 0) {
        klog_printf("[trophy] B21 verify MISMATCH @ va=0x%lx\n", va);
        phu_diag_log("trophy B21 verify MISMATCH");
        return 0;
    }

    klog_printf("[trophy] B21 RecoveryRequired setter disabled @ 0x%lx "
                "(= no flag set on new NPWR entries → UpdateSummaryFile gate WRITE path)\n", va);
    phu_diag_log("trophy B21 patched va=0x%lx", va);
    return 1;
}

/* ============================================================================
 * r19.55 — B22 RecoveryRequired READER bypass (4.x range fix)
 * ----------------------------------------------------------------------------
 * Companion CRITICAL à B20+B21 pour 4.x launch fw range trophy unlock chain.
 *
 * Target: FUN_01aa02b0 (4.03) / FUN_01aa0c20 (4.50) — reader function.
 * Caller chain:
 * - FUN_01a9d0f0 UpdateSummaryFile @ +0x7f reads flag → gate fires DELETE
 * - FUN_01a9dc30 GetRecoveryRequired (external API)
 *
 * Even with B21 preventing future SETS, if file ALREADY has flag=1 on disk
 * (from previous broken installs), this reader returns 1 → unlock chain fails
 * silently (UnlockTrophyJob → IsRecoveryRequired_composite → 0x80551611).
 *
 * Patch (5 bytes): `31 C0 88 02 C3`
 * 31 C0 xor eax, eax; return value = 0 (success)
 * 88 02 mov [rdx], al; *param_3 = 0 (no recovery)
 * C3 ret; (skip original file read + sceNetNtohl)
 *
 * Function prologue verified (byte-exact read):
 * 55 48 89 e5 41 57 41 56 53 48 83 ec 48... (16 bytes)
 * Patch overwrites first 5 bytes → caller gets clean rc=0 + flag=0.
 *
 * Side effect: original function read 0x30 bytes from file via FUN_01a90450 at
 * offset (file_handle + 0x6c). Patched version skips this read entirely — safe
 * because the only purpose was to extract the flag bit.
 *
 * 4.x range only (4.03 + 4.50). Other fws: VA=0 → skip-if-zero → no-op. */
static int do_b22_recovery_read_bypass_patch(pid_t shellcore_pid, uintptr_t shellcore_base,
                                              uintptr_t image_base) {
    const phu_trophy_fw_offsets_t *e = get_fw_offsets;
    if (!e || e->b22_recovery_read_va == 0) {
        return 1; /* skip-if-zero — fw doesn't need B22 (only 4.x range) */
    }

    uintptr_t va = shellcore_base + (e->b22_recovery_read_va - image_base);
    static const uint8_t B22_PATCH[5] = { 0x31, 0xC0, 0x88, 0x02, 0xC3 };
    uint8_t pre[5] = {0};
    uint8_t post[5] = {0};

    if (!prw::proc_read(shellcore_pid, va, pre, 5)) {
        klog_printf("[trophy] B22 read FAIL (va=0x%lx)\n", va);
        phu_diag_log("trophy B22 read FAIL va=0x%lx", va);
        return 0;
    }

    /* Already-patched detection (idempotent re-runs). */
    if (memcmp(pre, B22_PATCH, 5) == 0) {
        klog_printf("[trophy] B22 already patched (va=0x%lx) — skip\n", va);
        phu_diag_log("trophy B22 already patched");
        return 1;
    }

    /* Verify pre-bytes match expected function prologue (55 48 89 e5 41):
     * push rbp; mov rbp, rsp; push r15. Avoid patching wrong fn. */
    if (pre[0] != 0x55 || pre[1] != 0x48 || pre[2] != 0x89 ||
        pre[3] != 0xe5 || pre[4] != 0x41) {
        klog_printf("[trophy] B22 unexpected prologue %02x %02x %02x %02x %02x (va=0x%lx) — abort\n",
                    pre[0], pre[1], pre[2], pre[3], pre[4], va);
        phu_diag_log("trophy B22 pre-mismatch %02x%02x%02x%02x%02x",
                     pre[0], pre[1], pre[2], pre[3], pre[4]);
        return 0;
    }

    rollback_record(shellcore_pid, va, 5);

    if (!prw::proc_write(shellcore_pid, va, B22_PATCH, 5)) {
        klog_printf("[trophy] B22 write FAIL (va=0x%lx)\n", va);
        phu_diag_log("trophy B22 write FAIL");
        return 0;
    }
    kernel_mprotect(shellcore_pid, (intptr_t)(va & ~0xFFFUL), 0x1000,
                    PROT_READ | PROT_EXEC);

    if (!prw::proc_read(shellcore_pid, va, post, 5)) {
        klog_printf("[trophy] B22 verify-read FAIL\n");
        return 0;
    }
    if (memcmp(post, B22_PATCH, 5) != 0) {
        klog_printf("[trophy] B22 verify MISMATCH @ va=0x%lx\n", va);
        phu_diag_log("trophy B22 verify MISMATCH");
        return 0;
    }

    klog_printf("[trophy] B22 RecoveryRequired reader bypass @ 0x%lx "
                "(= force *param_3 = 0 → unlock chain proceeds even if on-disk flag set)\n", va);
    phu_diag_log("trophy B22 patched va=0x%lx", va);
    return 1;
}

/* ============================================================================
 * r19.39 — Trophy nuclear reset (cfg trophy_reset_pending = 1)
 * ----------------------------------------------------------------------------
 * When cfg key trophy_reset_pending == 1 + sentinel /user/data/PHU/trophy_reset_done
 * does NOT exist, executes a full wipe of user trophy state:
 * - /user/home/<uid_hex>/trophy/ (per user)
 * - /user/trophy/conf/ (Trophy v1 PS4 NPWR configs)
 * - /user/trophy2/nobackup/conf/ (Trophy v2 PS5 NPWR configs)
 * NEVER touches /user/system/share/trophy/ (= Sony seed for first-boot init).
 *
 * Anti-cascade: files are truncated to 0 bytes before deletion, with 50ms
 * sleep between files to avoid spamming Sony's daemon (which can panic on
 * rapid-fire directory removals — see trophy delete cascade incident memory).
 *
 * After completion, creates sentinel /user/data/PHU/trophy_reset_done so that
 * subsequent boots with cfg still = 1 don't re-execute wipe (loop prevention).
 * User must manually edit cfg back to 0 + delete sentinel to re-arm.
 * ============================================================================ */
/* r19.71 — SAFE trophy reset (= files only, NO rmdir).
 *
 * Lessons learned from cascade panic incident (= 2026-05-17):
 * - rmdir recursive on Sony state folders → daemon panic non-recoverable
 * - Even Safe Mode Rebuild won't recover
 *
 * SAFE approach:
 * - Target the 3 specific FILE types per NPWR:
 * /user/trophy2/nobackup/conf/<NPWR>/TROPHY.UCP (= global state)
 * /user/home/<uid_hex>/trophy2/nobackup/data/<NPWR>/TRPTITLE.DAT (= per-user state)
 * /user/np_uds/nobackup/conf/<NPWR>/uds.ucp (= UDS state)
 * - Truncate to 0 bytes first (= anti-cascade)
 * - Then unlink files
 * - Leave folders intact (= Sony daemon happy)
 * - 50ms sleep between deletes (= anti-cascade rate limit)
 */
static int phu_trophy_reset_delete_file_safe(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return 0; /* not found = nothing to do */
    if (!S_ISREG(st.st_mode)) return 0; /* not a regular file */

    /* Truncate to 0 bytes first (anti-cascade) */
    if (st.st_size > 0) {
        int fd = open(path, O_WRONLY | O_TRUNC, 0);
        if (fd >= 0) close(fd);
    }
    int rc = unlink(path);
    usleep(50000); /* 50ms anti-cascade */
    if (rc == 0) {
        klog_printf("[trophy_reset] DELETED %s\n", path);
        return 1;
    }
    return 0;
}

/* Enumerate NPWR folders in a base dir + delete one target file per NPWR.
 * Example: base="/user/trophy2/nobackup/conf", file="TROPHY.UCP"
 * iterates each NPWR_xxxxx folder, unlinks the target_file inside it.
 * Folders are KEPT intact. */
static int phu_trophy_reset_iter_npwr_files(const char *base, const char *target_file) {
    DIR *d = opendir(base);
    if (!d) return 0;

    int total = 0;
    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        /* NPWR folder name format: NPWR[0-9]{5}_NN (= 12 chars) */
        size_t len = strlen(entry->d_name);
        if (len < 4 || strncmp(entry->d_name, "NPWR", 4) != 0) continue;

        char file_path[512];
        int n = snprintf(file_path, sizeof(file_path), "%s/%s/%s",
                         base, entry->d_name, target_file);
        if (n <= 0 || (size_t)n >= sizeof(file_path)) continue;

        total += phu_trophy_reset_delete_file_safe(file_path);
    }
    closedir(d);
    return total;
}

extern "C" int phu_trophy_reset_check_and_execute(void) {
    if (g_phu_cfg.trophy_reset_pending == 0) {
        return 0; /* not triggered */
    }

    /* Loop prevention: if sentinel exists, log + skip (user must clean up to re-arm) */
    struct stat sentinel_st;
    if (stat("/user/data/PHU/trophy_reset_done", &sentinel_st) == 0) {
        klog_printf("[trophy_reset] cfg trophy_reset_pending=1 but sentinel "
                    "/user/data/PHU/trophy_reset_done exists — wipe already done. "
                    "To re-arm: edit cfg to 0 + delete sentinel file.\n");
        phu_diag_log("trophy_reset skip (sentinel exists, edit cfg+sentinel to re-arm)");
        return 0;
    }

    klog_printf("[trophy_reset] cfg trophy_reset_pending=1 detected — executing SAFE reset (r19.71)\n");
    phu_diag_log("trophy_reset BEGIN safe reset (files only)");
    phu_notify("PHU Trophy: safe reset in progress — DO NOT power off");

    int total = 0;

    /* Phase 1 — Trophy 2 global state (TROPHY.UCP per NPWR) */
    klog_printf("[trophy_reset] Phase 1: /user/trophy2/nobackup/conf/<NPWR>/TROPHY.UCP\n");
    total += phu_trophy_reset_iter_npwr_files("/user/trophy2/nobackup/conf", "TROPHY.UCP");

    /* Phase 2 — Trophy 2 per-user state (TRPTITLE.DAT per uid_hex per NPWR) */
    klog_printf("[trophy_reset] Phase 2: /user/home/<uid_hex>/trophy2/nobackup/data/<NPWR>/TRPTITLE.DAT\n");
    DIR *home = opendir("/user/home");
    if (home) {
        struct dirent *e;
        while ((e = readdir(home)) != NULL) {
            if (e->d_name[0] == '.') continue;
            /* Validate hex8 (= user_id format) */
            if (strlen(e->d_name) != 8) continue;
            bool is_hex = true;
            for (int i = 0; i < 8; i++) {
                char c = e->d_name[i];
                if (!((c >= '0' && c <= '9') ||
                      (c >= 'a' && c <= 'f') ||
                      (c >= 'A' && c <= 'F'))) {
                    is_hex = false;
                    break;
                }
            }
            if (!is_hex) continue;

            char user_data_path[256];
            snprintf(user_data_path, sizeof(user_data_path),
                     "/user/home/%s/trophy2/nobackup/data", e->d_name);
            klog_printf("[trophy_reset] iter user %s: %s\n", e->d_name, user_data_path);
            total += phu_trophy_reset_iter_npwr_files(user_data_path, "TRPTITLE.DAT");
        }
        closedir(home);
    } else {
        klog_printf("[trophy_reset] cannot opendir /user/home\n");
    }

    /* Phase 3 — UDS state (uds.ucp per NPWR) */
    klog_printf("[trophy_reset] Phase 3: /user/np_uds/nobackup/conf/<NPWR>/uds.ucp\n");
    total += phu_trophy_reset_iter_npwr_files("/user/np_uds/nobackup/conf", "uds.ucp");

    /* Create sentinel to prevent loop on next boot */
    int sfd = open("/user/data/PHU/trophy_reset_done", O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (sfd >= 0) {
        const char *msg = "PHU trophy reset done (r19.71 SAFE files-only). "
                          "Edit cfg trophy_reset_pending=0 + delete this file to re-arm.\n";
        ssize_t wn = write(sfd, msg, strlen(msg));
        (void)wn;
        close(sfd);
    }

    klog_printf("[trophy_reset] DONE: %d files deleted (SAFE, no folders touched). "
           "Cold reboot console before re-launching games.\n", total);
    phu_diag_log("trophy_reset DONE files=%d (safe files-only)", total);
    phu_notify("PHU Trophy: safe reset complete. Cold reboot console now.");
    return total;
}

extern "C" int phu_trophy_init_boot(void) {
    if (!g_phu_cfg.trophy_unlock_enabled) {
        return 0; /* master switch OFF — silent no-op */
    }

    klog_printf("[trophy] init_boot: master switch ENABLED\n");
    phu_diag_log("trophy init_boot: master ON, daemon_patch=%d client_inject=%d warn=%d whitelist='%s'",
                 g_phu_cfg.trophy_unlock_daemon_patch,
                 g_phu_cfg.trophy_unlock_client_inject,
                 g_phu_cfg.trophy_unlock_warn_notif,
                 g_phu_cfg.trophy_unlock_titleids);

    if (g_phu_cfg.trophy_unlock_warn_notif) {
        phu_trophy_show_warn_notif;
    }

    if (!g_phu_cfg.trophy_unlock_daemon_patch) {
        klog_printf("[trophy] B1 daemon_patch disabled — skipping SceShellCore patch\n");
        return 0;
    }

    /* fw guard — RE'd offsets are 9.40 specific. */
    if (!fw_is_supported) {
        const phu_fw_offsets_t *fw = phu_fw_offsets_current;
        klog_printf("[trophy] B1 fw=%s NOT supported — only 9.40 has RE'd string offsets. "
                    "Daemon patch disabled.\n",
                    fw && fw->fw_label ? fw->fw_label: "unknown");
        phu_diag_log("trophy B1 fw not supported: %s",
                     fw && fw->fw_label ? fw->fw_label: "unknown");
        return -1;
    }

    /* Resolve SceShellCore.elf via title_id (NPXS40082) — Sony daemon p_comm
     * fields are unreliable (e.g. SceShellUI's p_comm = "SceShellUIMain" on
     * 9.40 vs "SceShellUI" on 7.61), so libhijacker's Hijacker::getHijacker
     * (StringView) name-match was returning nullptr on first runtime test
     * (B1-r2 KO: "Hijacker::getHijacker FAILED — daemon not found"). PHU
     * already has libNineS title-id walker that handles this robustly. */
    struct proc *sc_proc = get_proc_by_title_id("NPXS40082");
    if (!sc_proc) {
        klog_printf("[trophy] B1 get_proc_by_title_id(NPXS40082) FAILED — "
                    "SceShellCore not found in allproc, abort\n");
        phu_diag_log("trophy B1 SceShellCore proc not found via title_id");
        return -1;
    }
    int shellcore_pid = phu_proc_get_pid(sc_proc);
    free(sc_proc); /* libNineS allocates via malloc; pid already extracted */

    if (shellcore_pid <= 0) {
        klog_printf("[trophy] B1 SceShellCore pid=%d invalid — abort\n", shellcore_pid);
        return -1;
    }

    UniquePtr<Hijacker> hj = Hijacker::getHijacker(shellcore_pid);
    if (!hj) {
        klog_printf("[trophy] B1 Hijacker::getHijacker(pid=%d) FAILED for SceShellCore — abort\n",
                    shellcore_pid);
        phu_diag_log("trophy B1 Hijacker getHijacker by pid failed: pid=%d", shellcore_pid);
        return -1;
    }
    uintptr_t shellcore_base = hj->imagebase;
    if (shellcore_pid <= 0 || shellcore_base == 0) {
        klog_printf("[trophy] B1 SceShellCore pid=%d base=0x%lx — invalid, abort\n",
                    shellcore_pid, shellcore_base);
        return -1;
    }
    klog_printf("[trophy] B1 SceShellCore.elf: pid=%d base=0x%lx\n",
                shellcore_pid, shellcore_base);
    phu_diag_log("trophy B1 SceShellCore: pid=%d base=0x%lx", shellcore_pid, shellcore_base);

    /* DMAP read needs kstuff alive for proc_read translate. PHU's helper
     * handles auto-pause / SMP. Probe + patch under the same kstuff window. */
    bool resumed = phu_kstuff_ctrl_temporary_resume_for_op;

    uintptr_t image_base = probe_image_base((pid_t)shellcore_pid, shellcore_base);
    int patched = 0;
    if (image_base != (uintptr_t)-1) {
        /* r19.10 — 10.01 boot diagnostic. Dumps trophy daemon singleton state
         * BEFORE patches so known exactly which inits are missing. No-op on
         * other fws (fw_label guard inside). Output → phu-klog + PHUdiag. */
        phu_trophy_diag_10_01((pid_t)shellcore_pid, shellcore_base, image_base);

        patched = do_daemon_patch((pid_t)shellcore_pid, shellcore_base,
                                  image_base, /*verify_pre*/ true);
    } else {
        klog_printf("[trophy] B1 probe FAILED — neither candidate image_base matched. "
                    "offsets may need re-verification.\n");
        phu_diag_log("trophy B1 probe failed: no candidate matched");
    }

    /* B3 — patch npbind.dat crypto bypass entries in SceShellCore (skip AES
     * validation of trophy signatures). Without B3 the fake 0x5A×128 secret
     * makes AES decrypt produce garbage → trophy register fails. Patch
     * 2 entry points (FUN_01a9dfe0 + FUN_01a9fe50) to `xor eax,eax; ret`. */
    int b3_patched = 0;
    int b4_patched = 0;
    int b5_patched = 0;
    int b5_lnc_patched = 0;
    int b8_path_b_patched = 1; /* default = "OK/not-needed" (overwritten if patch attempt fires) */
    int b9_path_b_vtable_patched = 1; /* default = "OK/not-needed" */
    int b10_path_b_entry_patched = 1; /* default = "OK/not-needed" */
    int b5_auth_bypass_patched = 1; /* default = "OK/not-needed" */
    if (image_base != (uintptr_t)-1) {
        b3_patched = do_crypto_bypass_patch((pid_t)shellcore_pid, shellcore_base,
                                            image_base);
        klog_printf("[trophy] B3 crypto bypass done: %d/2 functions patched\n", b3_patched);
        phu_diag_log("trophy B3: %d/2 patched", b3_patched);

        /* B4 — patch FUN_017266c0 (app inventory check). Without B4, daemon
         * reaches FUN_01d2b3f0 successfully thanks to B3 but exits silently
         * because the dump's title_id isn't in SceShellCore's app inventory
         * list (DAT_02ee7c08..DAT_02ee7c10). After B4, the inventory check
         * is forced to return success + category=2 for ALL apps. */
        b4_patched = do_app_inventory_bypass_patch((pid_t)shellcore_pid,
                                                   shellcore_base, image_base);
        klog_printf("[trophy] B4 app inventory bypass: %d/1 function patched\n", b4_patched);
        phu_diag_log("trophy B4: %d/1 patched", b4_patched);

        /* B5 — DISABLED on r10 (= post-r9 KP recovery).
         * Patching FUN_019f0660 system-wide enabled dev-only code paths in
         * SceShellUI that call copyin while holding a non-sleeping spinlock,
         * causing kernel panic with message
         * "copyin: SceShellUIMain has nonsleeping lock"
         * on r9 runtime test (2026-05-12). Trophy REGISTER (B1+B2+B3+B4)
         * does not need B5 — auth check is bypassed only for SystemDebug*
         * APIs (UnlockTrophy direct call). Register works via cmd 0x90016
         * which uses a different auth gate (FUN_019f1470) that games pass
         * natively.
         *
         * If want force-unlock later (= Phase B5b), would need a more
         * targeted patch — only the conditional branch in FUN_01ce1490
         * (the IPMI cmd 0x90018 handler) instead of FUN_019f0660 globally.
         * r19.57 audit H3 — Legacy do_auth_bypass_patch DELETED entirely; if
         * a future Phase B5b force-unlock is needed, re-implement using a per-fw
         * uint64_t field (read from g_trophy_fw_table[]). */
        b5_patched = -1; /* marker: not applied this build */
        klog_printf("[trophy] B5 SKIPPED (r9 KP root cause — too broad bypass)\n");
        phu_diag_log("trophy B5 skipped due to KP risk");

        /* r16 — B5_LNC: LncManager attr bypass. Last daemon-side gate
         * blocking trophy install for retail-launched apps. Surgical 2-byte
         * patch identified via RE 2026-05-13. */
        if (g_phu_cfg.trophy_lnc_attr_bypass_enabled) {
            b5_lnc_patched = do_lnc_attr_bypass_patch((pid_t)shellcore_pid,
                                                     shellcore_base, image_base);
            klog_printf("[trophy] B5_LNC LncManager attr bypass: %d/1 function patched\n",
                        b5_lnc_patched);
            phu_diag_log("trophy B5_LNC: %d/1 patched", b5_lnc_patched);
        } else {
            klog_printf("[trophy] B5_LNC disabled by cfg\n");
            b5_lnc_patched = -1;
        }

        /* r19.6 B8 — force path B in trophy register chain. Per-fw gated. */
        b8_path_b_patched = do_b8_path_b_force_patch((pid_t)shellcore_pid,
                                                     shellcore_base, image_base);
        klog_printf("[trophy] B8 path-B force: %s\n",
                    b8_path_b_patched ? "OK or NOT NEEDED": "FAILED");
        phu_diag_log("trophy B8 path-B-force: %d", b8_path_b_patched);

        /* r19.8 B9 — force path B INNER vtable check pass (FUN_01d808a0). */
        b9_path_b_vtable_patched = do_b9_path_b_vtable_patch((pid_t)shellcore_pid,
                                                              shellcore_base, image_base);
        klog_printf("[trophy] B9 path-B vtable: %s\n",
                    b9_path_b_vtable_patched ? "OK or NOT NEEDED": "FAILED");
        phu_diag_log("trophy B9 path-B-vtable: %d", b9_path_b_vtable_patched);

        /* r19.8 B10 — nuclear bypass FUN_01a8fc60 entry (path B). */
        b10_path_b_entry_patched = do_b10_path_b_entry_patch((pid_t)shellcore_pid,
                                                              shellcore_base, image_base);
        klog_printf("[trophy] B10 path-B entry bypass: %s\n",
                    b10_path_b_entry_patched ? "OK or NOT NEEDED": "FAILED");
        phu_diag_log("trophy B10 path-B-entry: %d", b10_path_b_entry_patched);

        /* r19.15 B12 — BindInfo::GetNpCommIdPtr force non-NULL (fix 0x8055391a). */
        int b12_commid_patched = do_b12_commid_force_patch((pid_t)shellcore_pid,
                                                            shellcore_base, image_base);
        klog_printf("[trophy] B12 commId force: %s\n",
                    b12_commid_patched ? "OK or NOT NEEDED": "FAILED");
        phu_diag_log("trophy B12 commId-force: %d", b12_commid_patched);

        /* r19.18 B13 — User::GetUser force success (fix 0x80553917 USER_NOT_FOUND). */
        int b13_getuser_patched = do_b13_user_getuser_patch((pid_t)shellcore_pid);
        klog_printf("[trophy] B13 User::GetUser: %s\n",
                    b13_getuser_patched ? "OK or NOT NEEDED": "FAILED");
        phu_diag_log("trophy B13 user-getuser: %d", b13_getuser_patched);

        /* r19.19 B14 — User::IsLoggedIn force true (fix 0x80553918 NOT_LOGGED_IN). */
        int b14_isloggedin_patched = do_b14_isloggedin_patch((pid_t)shellcore_pid);
        klog_printf("[trophy] B14 User::IsLoggedIn: %s\n",
                    b14_isloggedin_patched ? "OK or NOT NEEDED": "FAILED");
        phu_diag_log("trophy B14 is-logged-in: %d", b14_isloggedin_patched);

        /* r19.20 B15 — User::IsGuest force false (preemptive for offact users). */
        int b15_isguest_patched = do_b15_isguest_patch((pid_t)shellcore_pid);
        klog_printf("[trophy] B15 User::IsGuest: %s\n",
                    b15_isguest_patched ? "OK or NOT NEEDED": "FAILED");
        phu_diag_log("trophy B15 is-guest: %d", b15_isguest_patched);

        /* r19.21 B16 — FUN_019e92f0 user_status normalizer → always 1 (logged-in regular). */
        int b16_user_status_patched = do_b16_user_status_patch((pid_t)shellcore_pid,
                                                                shellcore_base, image_base);
        klog_printf("[trophy] B16 user_status: %s\n",
                    b16_user_status_patched ? "OK or NOT NEEDED": "FAILED");
        phu_diag_log("trophy B16 user-status: %d", b16_user_status_patched);

        /* r19.22 B17 — FUN_01ccdd40 bypass 4× MOV R15D, 0x8055391e (IpcJob Phase 5 helper). */
        int b17_391e_patched = do_b17_register_391e_patch((pid_t)shellcore_pid,
                                                           shellcore_base, image_base);
        klog_printf("[trophy] B17 0x8055391e bypass: %s\n",
                    b17_391e_patched ? "OK or NOT NEEDED": "FAILED");
        phu_diag_log("trophy B17 391e-bypass: %d", b17_391e_patched);

        /* r19.23 B18 — Force first-time path in FUN_01a6fcc0 (the orchestrator).
         * 3-byte surgical: TEST R12B,R12B → XOR R12B,R12B @ 0x01a6fd0a.
         * Forces JZ at 0x01a6fd0d always taken → first-time path → CMOVNZ
         * swallow @ 0x01a70382 catches 0x8055391e → return 0 success.
         * Universal fix: works regardless of WHERE 0x8055391e originates
         * (vtable+0x18 call return, FUN_01ce9a10 fail, loop exhaustion). */
        int b18_force_firsttime = do_b18_force_firsttime_path((pid_t)shellcore_pid,
                                                                shellcore_base, image_base);
        klog_printf("[trophy] B18 force first-time path: %s\n",
                    b18_force_firsttime ? "OK or NOT NEEDED": "FAILED");
        phu_diag_log("trophy B18 force-firsttime: %d", b18_force_firsttime);

        /* r19.39 B20 — IsDeprecatedVersion bypass (4.03 launch fw trophy display bug fix).
         * Sony's CreateUserDataFile sets version=0x10000 and IsDeprecatedVersion checks
         * against 0x10000 → always TRUE → UpdateSummaryFile DELETEs trpsummary.dat at
         * every unlock → profile shows 0/0/0/0. B20 patches to always FALSE. */
        if (g_phu_cfg.trophy_summary_bypass_enabled) {
            int b20_isdeprecated_patched = do_b20_isdeprecated_bypass_patch((pid_t)shellcore_pid,
                                                                              shellcore_base, image_base);
            klog_printf("[trophy] B20 IsDeprecatedVersion bypass: %s\n",
                        b20_isdeprecated_patched ? "OK or NOT NEEDED": "FAILED");
            phu_diag_log("trophy B20 isdeprecated-bypass: %d", b20_isdeprecated_patched);

            /* r19.39 B21 — RecoveryRequired setter disable.
             * Sony's FUN_01aa0150 (called from CreateUserDataFile) sets bit 0 of NPWR
             * entry header on creation → UpdateSummaryFile gate first condition TRUE
             * → DELETE path. B21 patches function to return 0 immediately without
             * executing the bit-set instruction. */
            int b21_recovery_setter_patched = do_b21_recovery_setter_disable_patch((pid_t)shellcore_pid,
                                                                                     shellcore_base, image_base);
            klog_printf("[trophy] B21 RecoveryRequired setter disable: %s\n",
                        b21_recovery_setter_patched ? "OK or NOT NEEDED": "FAILED");
            phu_diag_log("trophy B21 recovery-setter-disable: %d", b21_recovery_setter_patched);

            /* r19.55 B22 — RecoveryRequired READER bypass. Critical companion à B21:
             * force *param_3 = 0 même si on-disk flag set. Fixe le unlock chain
             * 4.x range qui silently fail à cause de FUN_01a6cd60 → 0x80551611. */
            int b22_recovery_read_patched = do_b22_recovery_read_bypass_patch((pid_t)shellcore_pid,
                                                                                shellcore_base, image_base);
            klog_printf("[trophy] B22 RecoveryRequired reader bypass: %s\n",
                        b22_recovery_read_patched ? "OK or NOT NEEDED": "FAILED");
            phu_diag_log("trophy B22 recovery-read-bypass: %d", b22_recovery_read_patched);
        } else if (g_phu_cfg.trophy_isdeprecated_bypass) {
            /* r19.67 — Granular B20-only safe fix (= mini menu trophy display 4.x).
             * Fixes Sony 4.03 launch fw IsDeprecatedVersion always-TRUE bug WITHOUT
             * touching B21 setter / B22 reader which can break Sony's commit chain.
             * Surgical fix: write path active for trpsummary.dat → mini menu OK. */
            int b20_isdeprecated_patched = do_b20_isdeprecated_bypass_patch((pid_t)shellcore_pid,
                                                                              shellcore_base, image_base);
            klog_printf("[trophy] B20-only (r19.67 safe fix) IsDeprecatedVersion bypass: %s\n",
                        b20_isdeprecated_patched ? "OK or NOT NEEDED": "FAILED");
            phu_diag_log("trophy B20-only safe fix: %d", b20_isdeprecated_patched);
        } else {
            klog_printf("[trophy] B20+B21+B22 skipped: trophy_summary_bypass_enabled=0 + trophy_isdeprecated_bypass=0 in cfg\n");
            phu_diag_log("trophy B20+B21+B22 skipped (both cfg disabled)");
        }

        /* r19.9 B5 — Debug auth bypass enables SystemDebugUnlockTrophy. On 10.01
         * path A+B broken → DebugUnlock is primary unlock path. Per-fw gate
         * (9.40/7.61 = 0, skip). KP risk: enables daemon Debug APIs, but on 10.01
         * NEEDED because standard RegisterContext is dead. */
        b5_auth_bypass_patched = do_b5_auth_bypass_patch((pid_t)shellcore_pid,
                                                         shellcore_base, image_base);
        klog_printf("[trophy] B5 auth bypass: %s\n",
                    b5_auth_bypass_patched ? "OK or NOT NEEDED": "FAILED");
        phu_diag_log("trophy B5 auth-bypass: %d", b5_auth_bypass_patched);
    } else {
        klog_printf("[trophy] B3+B4+B5_LNC+B8+B9+B10+B5 skipped — image_base probe failed at B1\n");
    }


    phu_kstuff_ctrl_restore_after_op(resumed);

    klog_printf("[trophy] init_boot done: B1=%d/4 B3=%d/2 B4=%d/1 B5_LNC=%d/1 "
                "B8=%d B9=%d B10=%d B5=%d (10.01 = full nuclear + DebugUnlock-ready)\n",
                patched, b3_patched, b4_patched, b5_lnc_patched,
                b8_path_b_patched, b9_path_b_vtable_patched, b10_path_b_entry_patched,
                b5_auth_bypass_patched);
    phu_diag_log("trophy init_boot: B1=%d/4 B3=%d/2 B4=%d/1 B5_LNC=%d/1 "
                 "B8=%d B9=%d B10=%d B5=%d (resumed=%d)",
                 patched, b3_patched, b4_patched, b5_lnc_patched,
                 b8_path_b_patched, b9_path_b_vtable_patched, b10_path_b_entry_patched,
                 b5_auth_bypass_patched, (int)resumed);
    (void)b5_patched; /* explicit ignore — old B5 disabled for safety */

    /* Success = B1+B3+B4+B5_LNC all applied. Without B5_LNC, daemon's commit
     * step bails at LncManager attr check (0x8094000F) for retail-launched apps.
     *
     * b3_patched: 2 = patched OR pre-Cronos disabled-by-design sentinel;
     * 0 = Cronos disabled-by-design (Sony auto-prepare);
     * both count as "done" for the gate. */
    bool b3_ok = (b3_patched == 2 || b3_patched == 0);
    bool all_ok = (patched == 4 && b3_ok && b4_patched == 1
                   && (b5_lnc_patched == 1
                       || !g_phu_cfg.trophy_lnc_attr_bypass_enabled));

    /* Set the done flags so apply_per_game can gate B2+B6+B7 on full daemon
     * readiness. If any phase is partial, B2+B6+B7 will skip cleanly. */
    g_b1_full_done = (patched == 4);
    g_b3_full_done = b3_ok;
    g_b4_full_done = (b4_patched == 1);
    g_b5_lnc_full_done = (b5_lnc_patched == 1
                          || !g_phu_cfg.trophy_lnc_attr_bypass_enabled);

    return all_ok ? 0: -1;
}

/* ============================================================================
 * r19.32 — phu_trophy_rollback_boot
 *
 * Restore SceShellCore to vanilla state by writing the saved pre-patch bytes
 * back to all recorded sites (B1+B3+B4+B5+B5_LNC). Called by probe at game-
 * vanish so the next game launch (PS4 BC or PS5 native) sees vanilla
 * SceShellCore — fixing the Sony PS4 BC trophy promote chain that's broken
 * by the patches (sceNpTrophyVshPromoteCheckRecoveryRequired2 0x80551618).
 *
 * Returns 0 on success (or no-op if nothing to rollback), -1 on partial fail
 * (some sites not restored — user may need to reboot for clean PS4 BC).
 * ============================================================================ */
extern "C" int phu_trophy_rollback_boot(void) {
    if (!g_trophy_lazy_init_done && g_rollback_count == 0) {
        return 0; /* No-op: patches never applied this session */
    }

    klog_printf("[trophy] rollback_boot: restoring %d sites (lazy=%d, full=%d)\n",
                g_rollback_count, (int)g_trophy_lazy_init_done, (int)g_rollback_full);
    phu_diag_log("trophy rollback: sites=%d lazy=%d full=%d",
                 g_rollback_count, (int)g_trophy_lazy_init_done, (int)g_rollback_full);

    if (g_rollback_count == 0) {
        /* Edge case: lazy flag set but registry empty (init_boot bailed early
         * before any patch). Just clear the flag. */
        g_trophy_lazy_init_done = false;
        return 0;
    }

    /* Re-resolve current SceShellCore pid: if Sony respawned it since the
     * patches were applied, the new instance is vanilla and the saved VAs
     * may not even be valid in the new address space. Skip rollback in that
     * case — new SceShellCore is already in the state want. */
    struct proc *sc_proc = get_proc_by_title_id("NPXS40082");
    if (!sc_proc) {
        klog_printf("[trophy] rollback: SceShellCore not found — clearing registry only\n");
        phu_diag_log("trophy rollback: SceShellCore not found");
        g_rollback_count = 0;
        g_rollback_full = false;
        g_b1_full_done = g_b3_full_done = g_b4_full_done = g_b5_lnc_full_done = false;
        g_trophy_lazy_init_done = false;
        return 0;
    }
    pid_t current_pid = (pid_t)phu_proc_get_pid(sc_proc);
    free(sc_proc);
    if (current_pid != g_rollback_shellcore_pid) {
        klog_printf("[trophy] rollback: SceShellCore respawned (old pid=%d new=%d) — "
                    "new instance is vanilla, just clearing registry\n",
                    (int)g_rollback_shellcore_pid, (int)current_pid);
        phu_diag_log("trophy rollback: SceShellCore respawned (old=%d new=%d)",
                     (int)g_rollback_shellcore_pid, (int)current_pid);
        g_rollback_count = 0;
        g_rollback_full = false;
        g_b1_full_done = g_b3_full_done = g_b4_full_done = g_b5_lnc_full_done = false;
        g_trophy_lazy_init_done = false;
        return 0;
    }

    /* Pause kstuff for safe DMAP operations (same as init_boot path). */
    bool resumed = phu_kstuff_ctrl_temporary_resume_for_op;

    int success = 0;
    int total = g_rollback_count;
    for (int i = 0; i < total; i++) {
        const auto &slot = g_rollback_sites[i];
        if (slot.size == 0 || slot.size > sizeof(slot.bytes)) continue;

        if (!prw::proc_write(current_pid, slot.va, slot.bytes, slot.size)) {
            klog_printf("[trophy] rollback FAIL @ site %d (va=0x%lx size=%u)\n",
                        i, slot.va, slot.size);
            phu_diag_log("trophy rollback FAIL site=%d va=0x%lx", i, slot.va);
            continue;
        }
        /* Flush µop cache / dcache same way as patch did. PROT_READ|EXEC for
         * code pages (B3/B4/B5/B5_LNC), PROT_READ for string data (B1). The
         * mprotect is best-effort — write may still take effect without it. */
        kernel_mprotect(current_pid, (intptr_t)(slot.va & ~0xFFFUL), 0x1000,
                        PROT_READ | PROT_EXEC);
        success++;
    }

    phu_kstuff_ctrl_restore_after_op(resumed);

    klog_printf("[trophy] rollback_boot: %d/%d sites restored\n", success, total);
    phu_diag_log("trophy rollback done: %d/%d", success, total);

    /* Clear registry + reset all flags regardless of partial success. If some
     * sites failed, the SceShellCore is in inconsistent state — next lazy
     * init will read pre-bytes again and might find mixed (vanilla+patched)
     * state which it will patch / leave as-is per pre-byte verification. */
    g_rollback_count = 0;
    g_rollback_full = false;
    g_rollback_shellcore_pid = -1;
    g_rollback_shellcore_base = 0;
    g_b1_full_done = false;
    g_b3_full_done = false;
    g_b4_full_done = false;
    g_b5_lnc_full_done = false;
    g_trophy_lazy_init_done = false;

    return (success == total) ? 0: -1;
}

extern "C" int phu_trophy_apply_per_game(int game_pid, const char *titleid) {
    if (!g_phu_cfg.trophy_unlock_enabled) return 0;
    if (!g_phu_cfg.trophy_unlock_client_inject) return 0;
    if (game_pid <= 0) return -1;

    /* r19.32 — PS5 native check FIRST (moved up before boot-flags gate).
     * PS4 BC titles (CUSA, BLES, NPJB, PCAS) are fpkg-installed = Sony installer
     * wrote trophies via Trophy 1 path. Sony's PS4 BC trophy promote chain
     * (sceNpTrophyVshPromoteCheckRecoveryRequired2) is BROKEN by the B1/B3/B4/
     * B5_LNC patches on SceShellCore — patches return 0x80551618 → NPDRM
     * license deletion → game launch aborted. Bail out IMMEDIATELY for PS4 BC
     * so never triggered lazy init_boot below. */
    if (!trophy_is_ps5_native(titleid)) {
        klog_printf("[trophy] apply_per_game: '%s' not PS5 native (PPSA*/PPSB*) — "
                    "skip (Sony native trophy chain handles PS4 BC fpkg games; "
                    "PHU trophy bypass is for raw PS5 dumps only)\n",
                    titleid ? titleid: "(null)");
        return 0;
    }

    if (!trophy_titleid_in_whitelist(titleid)) {
        klog_printf("[trophy] apply_per_game: titleid '%s' not in whitelist — skip\n",
                    titleid ? titleid: "(null)");
        return 0;
    }

    /* r19.56 hotfix-3 — BLACKLIST check. User can set `trophy_skip_titleids` in cfg
     * to opt-out specific games from PHU trophy chain entirely. Useful when a
     * specific game (e.g. Days Gone PPSA28180) fails to launch with PHU patches
     * active. PHU returns 0 IMMEDIATELY without touching SceShellCore → Sony's
     * native trophy promote chain works → game launches normally.
     * Default empty = no skip = no impact for normal users. */
    if (trophy_titleid_in_skiplist(titleid)) {
        klog_printf("[trophy] apply_per_game: titleid '%s' in skip list — PHU "
                    "trophy chain bypassed (cfg trophy_skip_titleids), "
                    "SceShellCore stays VANILLA → Sony chain handles game\n",
                    titleid ? titleid: "(null)");
        phu_diag_log("trophy skip-list bypass: tid=%s", titleid);
        return 0;
    }

    /* r19.32 — LAZY init_boot: apply SceShellCore patches (B1+B3+B4+B5_LNC)
     * on FIRST PS5 native + whitelisted game-detect, not at probe boot.
     * Rationale: booting with patches applied breaks PS4 BC game launch
     * via Sony's sceNpTrophyVshPromoteCheckRecoveryRequired2 0x80551618
     * cascade (NPDRM license deletion). Deferring keeps SceShellCore vanilla
     * until the user actually needs trophy infrastructure for a PS5 dump.
     *
     * Paired with phu_trophy_rollback_boot called at game-vanish: that
     * function writes the saved pre-patch bytes back to SceShellCore and
     * clears g_trophy_lazy_init_done, so next launch (PS4 BC or PS5 native)
     * sees a vanilla SceShellCore. Result: polyvalent session — user can
     * freely alternate PS5 (trophy ON) and PS4 BC (Sony chain intact)
     * without rebooting. */

    /* r19.32 — cross-session install detection BEFORE lazy init. If trophies
     * are already installed from a previous PHU session, don't need to
     * patch SceShellCore at all for this game — the install is idempotent
     * and gameplay trophy ops work via the existing TROPHY.UCP. Skipping
     * lazy init here keeps SceShellCore vanilla even when a PS5 native
     * game runs, which means PS4 BC games launched right after also work
     * without needing the rollback step. Net result: less patch churn and
     * cleaner SceShellCore state when re-playing already-installed games. */
    /* r19.50 multi-user FINAL fix (Lestat 7.61 audit 2026-05-19):
     *
     * Regression history:
     * r19.4 (May 13): patches PERSISTENT (init_boot at probe boot, no
     * rollback) → user2 launch was fast-path (already_
     * installed → return 0) AND succeeded because the
     * game's NATURAL sceNpTrophy2RegisterContext call
     * fired against a STILL-PATCHED SceShellCore →
     * Sony daemon registered user2 OK → trophies instant.
     * r19.32 (May 16): introduced LAZY init_boot + rollback_boot at game-
     * vanish (= polyvalent PS5↔PS4 BC). Side effect:
     * SceShellCore returns to VANILLA after each game.
     * r19.48 (May 18): tried to fix multi-user via skip_sceshellcore_patches
     * (run B7+B2+B6 for new user but skip lazy_init).
     * BUG: B6 RegisterContext hits a VANILLA daemon →
     * B1/B3/B5_LNC gates absent → daemon refuses →
     * user2 sees ZERO trophies.
     *
     * FIX r19.50: always run lazy_init for PS5 native games, regardless of
     * already_installed. This restores the r19.4 behavior:
     * - patches alive during the entire PS5 native session
     * - game's natural register call (Sony's own code path) succeeds for
     * ANY foreground user, not just the one PHU's B6 targets
     * - rollback at game-vanish still runs → PS4 BC polyvalent preserved
     *
     * Cost extra vs r19.48: ~500ms DMAP writes per PS5 native launch (B1+B3+
     * B4+B5_LNC patches, idempotent if already-patched bytes). B7 still
     * skip-if-exists, B2 still per-process, B6 idempotent (rc=0x80553900 on
     * already-registered user). Net: user2/3/4... see trophies instantly. */

    /* r19.56 hotfix-2 — RESTORE r19.32/r19.44 BEHAVIOR: check already_installed
     * BEFORE lazy_init. If TROPHY.UCP exists from previous PHU session, return
     * IMMEDIATELY without applying any SceShellCore patches. This keeps the
     * daemon VANILLA → Sony's sceNpTrophyVshPromoteCheckRecoveryRequired2
     * succeeds for ALL games (PS4 BC + PS5 native) → no launch abort cascade.
     *
     * Multi-user impact: user2 launches → already_installed=true → patches
     * skipped → game's natural register fires against VANILLA daemon. On 9.40
     * baseline (Arksama main console), this is fine (Sony Path B default works).
     * On 10.01 Cronos (offact strict checks), user2 might need re-install — but
     * trade-off acceptable to fix the game-won't-launch cascade.
     *
     * r19.44 baseline behavior restored exactly.
     *
     * ============================================================================
     * r19.57 audit 2026-05-20 — REVERT r19.56 hotfix-2 ENTIRELY
     * ============================================================================
     *
     * Multi-user regression history (cross-check user diag + memory):
     *
     * r19.4 (May 13): patches PERSISTENT (init_boot at probe boot, NO
     * rollback) → user2 sees patches alive → trophies OK.
     * r19.32 (May 16): LAZY init_boot + rollback at game-vanish (polyvalent
     * PS5↔PS4 BC). Side-effect: SceShellCore reverts to
     * VANILLA between game cycles. + fast-path skip when
     * already_installed → user2 launches with TROPHY.UCP
     * present → fast-path skips lazy_init → game's natural
     * RegisterContext hits VANILLA daemon → ZERO trophies.
     * r19.48 (May 18): Tentative fix via skip_sceshellcore_patches flag —
     * still broken (Lestat 7.61 audit confirmed B6 hit
     * vanilla SceShellCore).
     * r19.50 (May 19): Removed fast-path skip entirely → ALWAYS run lazy_init
     * for PS5 native, regardless of already_installed flag.
     * This restored r19.4 behavior. Multi-user worked.
     * r19.56 hotfix-2: RE-INTRODUCED fast-path skip "to keep SceShellCore
     * vanilla and protect PS4 BC trophy promote chain".
     * But that protection is REDUNDANT because rollback_boot
     * at game-vanish already restores vanilla. The fast-path
     * was solving a phantom problem.
     *
     * Why r19.56 hotfix-2 was over-cautious:
     *
     * Sony's sceNpTrophyVshPromoteCheckRecoveryRequired2 runs at GAME LAUNCH
     * (before the PHU detects the pid). At that moment SceShellCore state is:
     * - At probe boot: vanilla → Sony check passes ✓
     * - After previous vanish: rollback_boot restored vanilla → passes ✓
     * - During PS5 native run: patches active, but no new game launches
     * during this window (PS5 cannot run 2 games concurrently)
     *
     * → The fast-path skip protected against a scenario that doesn't exist.
     * It only broke multi-user (r19.32 bug pattern) and broke 4.03 trpsummary
     * regeneration (B6 never fires → UpdateSummaryFile never invoked with
     * B20+B21+B22 active → trpsummary.dat never written → profile empty).
     *
     * Fix: ALWAYS run lazy_init + B7+B2+B6 for PS5 native, even if already-
     * installed. B7 is skip-if-exists (idempotent). B2 is per-process (always
     * needed). B6 is idempotent (rc=0x80553900 on already-registered user) —
     * AND its execution triggers UpdateSummaryFile in Sony's daemon, which is
     * exactly what 4.03 trpsummary regen needs and what multi-user needs to
     * register a new user against the patched daemon.
     *
     * Cost vs fast-path: ~500ms extra DMAP writes per PS5 native launch (B1+
     * B3+B4+B5_LNC are idempotent if pre-patched bytes). Acceptable trade-off.
     *
     * User confirmation 2026-05-20: "r19.44 = source de vérité, à chaque
     * changement d'user on recommence un nouveau cycle". The r19.44 baseline
     * runs the FULL chain on every game cycle regardless of already-installed
     * state. This is the correct behavior.
     * ============================================================================ */
    if (phu_trophy_already_installed(titleid)) {
        /* r19.68 — Per-fw cfg control of force-full-chain re-apply.
         *
         * Hyndrid confirmed r19.38 worked perfectly on 12.00 (= had vanilla-preserved
         * shortcut). r19.57 changed to "always force chain" which broke mini menu
         * trophy display on permissive fws (9.40 etc.) because Sony's background
         * trpsummary.dat updates post-vanish hit vanilla daemon and fail.
         *
         * Solution: 2 cfg keys split by fw class:
         * trophy_force_full_chain_4_03 = 1 (default) → 4.03 strict needs re-apply
         * trophy_force_full_chain_other = 0 (default) → other fws preserve vanilla
         * = r19.38 behavior, mini menu OK */
        const phu_trophy_fw_offsets_t *e_check = get_fw_offsets;
        bool is_4_03 = (e_check && e_check->fw_label
                        && strcmp(e_check->fw_label, "4.03") == 0);
        uint8_t force = is_4_03 ? g_phu_cfg.trophy_force_full_chain_4_03
: g_phu_cfg.trophy_force_full_chain_other;

        if (!force) {
            klog_printf("[trophy] r19.68 vanilla-preserved shortcut: '%s' already installed "
                   "(fw=%s, force_chain_%s=0) — skip B7+B2+B6 + LAZY init "
                   "(mini menu trophy display preserved)\n",
                   titleid, e_check && e_check->fw_label ? e_check->fw_label: "?",
                   is_4_03 ? "4_03": "other");
            phu_diag_log("trophy r19.68 vanilla-preserved skip: tid=%s fw=%s",
                       titleid,
                       e_check && e_check->fw_label ? e_check->fw_label: "?");
            return 0;
        }

        klog_printf("[trophy] r19.68 force-full-chain: '%s' already installed but "
               "fw=%s force_chain_%s=1 → re-apply patches\n",
               titleid, e_check && e_check->fw_label ? e_check->fw_label: "?",
               is_4_03 ? "4_03": "other");
    }

    /* r19.32 — LAZY init_boot fires on FIRST PS5 native + whitelisted game-
     * detect, deferred from probe boot to avoid breaking PS4 BC trophy promote
     * chain. Rollback at game-vanish restores vanilla for the next session. */
    if (!g_trophy_lazy_init_done) {
        klog_printf("[trophy] LAZY init_boot triggered by first PS5 native game: %s\n",
                    titleid);
        phu_diag_log("trophy lazy init_boot: trigger tid=%s pid=%d",
                     titleid, game_pid);
        int init_rc = phu_trophy_init_boot;
        /* r19.56 hotfix-3 H-4: only set the flag if init_boot fully succeeded.
         * On partial failure (some patches OK but not all), leave flag false so
         * next game-detect cycle can retry. Prevents getting stuck with
         * lazy_init_done=true but B1/B3/B4/B5_LNC done flags all false. */
        if (init_rc == 0) {
            g_trophy_lazy_init_done = true;
        } else {
            klog_printf("[trophy] LAZY init_boot returned %d — flag NOT set, will retry "
                        "on next game-detect cycle\n", init_rc);
            phu_diag_log("trophy lazy init_boot partial-fail rc=%d (will retry)", init_rc);
        }
    }

    /* CRITICAL: B2/B6/B7 only run when B1+B3+B4+B5_LNC all succeeded at boot.
     * A partial daemon-side patch leaves SceShellCore in a half-bypassed gate
     * state — feeding it a register-context request would trigger an undefined
     * path. If any phase partial, skip cleanly and wait for persistence re-apply. */
    if (!g_b1_full_done || !g_b3_full_done || !g_b4_full_done || !g_b5_lnc_full_done) {
        klog_printf("[trophy] apply_per_game SKIP: B1=%d B3=%d B4=%d B5_LNC=%d "
                    "(lazy init_boot did not complete all patches)\n",
                    (int)g_b1_full_done, (int)g_b3_full_done,
                    (int)g_b4_full_done, (int)g_b5_lnc_full_done);
        return 0;
    }

    klog_printf("[trophy] apply_per_game: pid=%d titleid='%s'\n",
                game_pid, titleid ? titleid: "(null)");
    phu_diag_log("trophy apply: pid=%d tid=%s", game_pid, titleid ? titleid: "?");

    /* ========================================================================
     * r19.61 — Per-user already-installed shortcut
     * ------------------------------------------------------------------------
     * If the current foreground PSN user already has the NPWR state file
     * (TRPTITLE.DAT for PS5 native, trophy.img for PS4 BC) under their
     * /user/home/<uid_hex>/ tree, Sony's natural trophy chain has already
     * registered this NPWR for this user. Re-firing B7+B2+B6 here would:
     * - Re-copy npbind.dat (idempotent — harmless but I/O)
     * - Re-inject FAKE NpAsmClient secret/title → CORRUPTS save-triggered
     * trophy unlock chain (Sony's game-side logic that detects "user
     * completed quest X in their save → silently unlock trophy Y" can't
     * validate against the fake secret → unlock fails silently)
     * - Re-call sceNpTrophy2RegisterContext → potentially reset state
     *
     * Skipping ensures Sony's natural chain reads the existing state, save
     * logic triggers historical trophy unlocks normally, and B1/B3/B4/B5_LNC
     * stay applied (= daemon-side bypasses preserved for 4.03/6.02/Cronos
     * strict checks).
     *
     * Multi-user safe: the check is per-uid_hex path, so user1's install
     * does NOT make user2's chain skip. User2 first launch → no state →
     * fire chain → register → state created → subsequent launches skip.
     *
     * Empirical RE 2026-05-21 confirmed Sony's 3-level storage architecture
     * (sponsor global / state per-user / summary per-user). See
     * notes/PS5 Reference/PS5 Trophy Filesystem Map (9.40 RE).md for details.
     * ======================================================================== */
    {
        int current_uid = 0;
        int us_rc = sceUserServiceGetForegroundUser(&current_uid);
        if (us_rc == 0 && current_uid > 0
            && phu_trophy_already_installed_for_user(titleid, current_uid))
        {
            klog_printf("[trophy] r19.61 per-user shortcut: tid=%s uid=%08x — state EXISTS, "
                        "skip B7+B2+B6 (daemon patches stay alive, Sony's natural chain "
                        "preserved → save-triggered unlocks work)\n",
                        titleid, (unsigned int)current_uid);
            phu_diag_log("trophy r19.61 shortcut: tid=%s uid=%08x skip B7+B2+B6 (state preserved)",
                         titleid, (unsigned int)current_uid);
            return 0;
        }
        if (us_rc != 0) {
            klog_printf("[trophy] r19.61 per-user check: sceUserServiceGetForegroundUser rc=%d "
                        "— can't determine current uid, fall through to full chain\n", us_rc);
        }
    }

    /* ========================================================================
     * Phase B7 — Path A: copy game's trophy files into daemon canonical
     * appmeta path. MUST happen BEFORE B6 RegisterContext call, because the
     * daemon's commit step opens npbind.dat from /system_data/priv/appmeta/.
     * Raw dumps have files only in /user/app/<TID>/sce_sys/trophy2/; B7
     * mirrors them into the daemon-readable path. Idempotent (skip if exists).
     * ======================================================================== */
    if (g_phu_cfg.trophy_appmeta_setup_enabled && titleid && titleid[0]) {
        int b7_rc = phu_trophy_setup_appmeta(titleid);
        klog_printf("[trophy] B7 setup_appmeta returned %d for %s\n",
                    b7_rc, titleid);
    } else {
        klog_printf("[trophy] B7 disabled by cfg — skipping appmeta file copy\n");
    }

    /* ========================================================================
     * Phase B2 — client-side cache inject into libSceNpManager DAT_01063128.
     *
     * Architecture (validated 2026-05-12 via RE):
     *
     * DAT_01063128 = libSceNpManager.sprx + 0x63128 (image_base 0x01000000)
     * = global long *, points to a 200-byte NpAsmClient singleton struct.
     *
     * Struct layout:
     * +0x14 16B NpTitleId (format: "PPSAxxxxx_00", strlen=12, [9]='_')
     * +0x24 128B secret (16 × 8-byte chunks)
     * +0xa4 1B is_fake_or_external flag (set by SetNpTitleId)
     * +0xa5 1B cache_populated_old_sdk (set by FUN_0102df30 param4=1)
     * +0xa6 1B cache_populated_new_sdk (set by FUN_0102df80)
     * +0xbc 4B subsystem_state (must == 4 or 5 to pass FUN_0102e080)
     *
     * For sceNpAsmClientGetNpTitleId to return success (= cache hit), EITHER
     * +0xa5 OR +0xa6 must != 0. The function copies +0x14 (title_id) and
     * +0x24 (secret) to caller's out buffers. If these values are non-zero
     * and well-formed, the game proceeds to call SceShellCore (B1-patched
     * to accept "AAAA00000" — but a valid NpTitleId derived from the game's
     * own titleid is provided anyway).
     *
     * Timing: the struct is allocated by FUN_0102d920 (the NpAsmClient ctor),
     * called externally when game first touches libSceNpManager APIs (account
     * info, NpUserId, trophy register, etc.). Poll DAT_01063128 for up to
     * 5s to catch the allocation (longer would block the probe pipeline).
     * ======================================================================== */

    if (!fw_is_supported) {
        klog_printf("[trophy] B2 fw unsupported — skip client inject\n");
        return -1;
    }
    /* r19.4 — per-fw lookup once at top, reused for B2 DAT+anchor + B6 r15 below. */
    const phu_trophy_fw_offsets_t *e = get_fw_offsets;
    if (!e) {
        klog_printf("[trophy] B2 get_fw_offsets NULL — skip\n");
        return -1;
    }

    /* Resolve game-side libSceNpManager.sprx base via kernel_dynlib_handle +
     * dlsym on a known exported symbol. Use sceNpIntGetNpTitleIdSecret
     * (RE'd @ 0x01015310 on 9.40 / 0x01014fe0 on 7.61) as anchor.
     *
     * Why not Hijacker::getHijacker(game_pid) ? KO on B2-r5 runtime test:
     * "Hijacker::getHijacker(pid=100) FAILED — daemon not found". The game
     * process's SharedObject struct isn't fully populated at game-detect
     * time (race with game's own dyn-lib loader). kernel_dynlib_handle is
     * a separate path that PHU already uses successfully for FPS hooks.
     *
     * 5s retry loop in case libSceNpManager loading is still in progress. */
    uint32_t npmgr_handle = 0;
    int dh_retry;
    for (dh_retry = 0; dh_retry < 10; dh_retry++) {
        if (kernel_dynlib_handle(game_pid, "libSceNpManager.sprx", &npmgr_handle) == 0
            && npmgr_handle != 0) {
            break;
        }
        npmgr_handle = 0;
        usleep(500000);
    }
    if (npmgr_handle == 0) {
        klog_printf("[trophy] B2 libSceNpManager.sprx NOT loaded in game (pid=%d) after 5s — "
                    "game doesn't use Np APIs, skip B2 (B6 still attempts via libSceNpTrophy2)\n",
                    game_pid);
        phu_diag_log("trophy B2 libSceNpManager handle KO pid=%d — B6 still tried", game_pid);
        /* r19.7 fix: on games without libSceNpManager loaded (PPSA27360 + PPSA23226
         * on 10.01), B2 cache inject is moot but B6 force-install via libSceNpTrophy2
         * pt_call can still register trophies via the daemon (B3+B4+B5_LNC+B8 all
         * already applied at boot). Previously this early-return blocked B6 entirely. */
        int b6_rc = phu_trophy_force_install_via_ptcall(game_pid, titleid);
        klog_printf("[trophy] B6 (B2-skipped path) returned rc=%d\n", b6_rc);
        phu_diag_log("trophy B6 (B2-skip) rc=%d tid=%s", b6_rc, titleid ? titleid: "?");
        return 0;
    }

    /* dlsym the anchor symbol to derive lib base. */
    intptr_t anchor_va = kernel_dynlib_dlsym(game_pid, npmgr_handle,
                                             "sceNpIntGetNpTitleIdSecret");
    if (anchor_va <= 0) {
        klog_printf("[trophy] B2 dlsym(sceNpIntGetNpTitleIdSecret) FAILED on libSceNpManager "
                    "(handle=%u, ret=%ld) — abort\n", npmgr_handle, (long)anchor_va);
        phu_diag_log("trophy B2 dlsym anchor failed pid=%d handle=%u ret=%ld",
                     game_pid, npmgr_handle, (long)anchor_va);
        return -1;
    }
    /* r19.4 — per-fw anchor offset (9.40 = 0x15310, 7.61 = 0x14fe0).
     * lib_base_runtime = dlsym(sceNpIntGetNpTitleIdSecret) - np_anchor_offset. */
    uintptr_t npmgr_base = (uintptr_t)anchor_va - e->np_anchor_offset;
    klog_printf("[trophy] B2 libSceNpManager resolved: handle=%u anchor=0x%lx base=0x%lx "
                "(after %d retries)\n",
                npmgr_handle, (uintptr_t)anchor_va, npmgr_base, dh_retry);

    /* r19.4 — per-fw DAT offset (9.40 = 0x63128, 7.61 = 0x63118 shifted -0x10). */
    const uintptr_t DAT_OFFSET = e->np_dat_offset;
    uintptr_t dat_va = npmgr_base + DAT_OFFSET;

    klog_printf("[trophy] B2 libSceNpManager base=0x%lx DAT_01063128 va=0x%lx\n",
                npmgr_base, dat_va);

    /* DMAP needs kstuff alive. */
    bool resumed = phu_kstuff_ctrl_temporary_resume_for_op;

    /* Poll for DAT_01063128 != 0 (= NpAsmClient ctor has run in the game).
     * 5s max — libSceNpManager is normally init'd within the first 1-2s of
     * game launch (account/user info call paths). Longer poll blocks probe
     * pipeline (cheats, patches, FPS hook). If still NULL after 5s, give up
     * — user can re-launch game to re-trigger apply_per_game. */
    uintptr_t struct_va = 0;
    int poll_iter;
    for (poll_iter = 0; poll_iter < 10; poll_iter++) { /* 10 × 500ms = 5s max */
        if (prw::proc_read((pid_t)game_pid, dat_va, &struct_va, sizeof(struct_va)) &&
            struct_va != 0) {
            break;
        }
        struct_va = 0;
        usleep(500000); /* 500ms */
    }

    if (struct_va == 0) {
        klog_printf("[trophy] B2 DAT singleton still NULL after 5s — game never "
                    "initialized NpAsmClient, skip B2 (B6 still attempts)\n");
        phu_diag_log("trophy B2 DAT NULL after 5s pid=%d tid=%s — B6 still tried",
                     game_pid, titleid ? titleid: "?");
        phu_kstuff_ctrl_restore_after_op(resumed);
        /* r19.7 fix: same as libSceNpManager-not-loaded path above — try B6
         * directly since it uses libSceNpTrophy2 (not NpManager). */
        int b6_rc = phu_trophy_force_install_via_ptcall(game_pid, titleid);
        klog_printf("[trophy] B6 (B2-DAT-null path) returned rc=%d\n", b6_rc);
        phu_diag_log("trophy B6 (B2-skip-DAT) rc=%d tid=%s", b6_rc, titleid ? titleid: "?");
        return 0;
    }

    klog_printf("[trophy] B2 NpAsmClient struct allocated @ 0x%lx (after %d polls)\n",
                struct_va, poll_iter);

    /* Diagnostic read: current state of flags + subsystem_state. */
    uint8_t flag_a4 = 0xFF, flag_a5 = 0xFF, flag_a6 = 0xFF, flag_b8 = 0xFF;
    uint32_t state_bc = 0xFFFFFFFF;
    prw::proc_read((pid_t)game_pid, struct_va + 0xa4, &flag_a4, 1);
    prw::proc_read((pid_t)game_pid, struct_va + 0xa5, &flag_a5, 1);
    prw::proc_read((pid_t)game_pid, struct_va + 0xa6, &flag_a6, 1);
    prw::proc_read((pid_t)game_pid, struct_va + 0xb8, &flag_b8, 1);
    prw::proc_read((pid_t)game_pid, struct_va + 0xbc, &state_bc, 4);
    klog_printf("[trophy] B2 PRE-inject state: +0xa4=%u +0xa5=%u +0xa6=%u +0xb8=%u +0xbc=0x%x\n",
                flag_a4, flag_a5, flag_a6, flag_b8, state_bc);
    phu_diag_log("trophy B2 pre state: a4=%u a5=%u a6=%u b8=%u bc=0x%x",
                 flag_a4, flag_a5, flag_a6, flag_b8, state_bc);

    /* Build fake NpTitleId: "<TID>_00" exactly 12 chars + 4 nulls = 16B.
     * Validation in sceNpAsmClientSetNpTitleId: strlen==12 AND [9]=='_'.
     * Titleids in PHU are 9 chars (PPSAxxxxx / CUSAxxxxx) — perfect fit. */
    char fake_title_id[16] = {0};
    if (titleid && titleid[0]) {
        size_t tlen = strlen(titleid);
        if (tlen >= 9) {
            memcpy(fake_title_id, titleid, 9);
            fake_title_id[9] = '_';
            fake_title_id[10] = '0';
            fake_title_id[11] = '0';
            /* fake_title_id[12..15] stay 0 */
        } else {
            /* titleid too short — fall back to placeholder. */
            memcpy(fake_title_id, "PPSA00000_00", 12);
        }
    } else {
        memcpy(fake_title_id, "PPSA00000_00", 12);
    }

    /* Build fake secret: 128 bytes of 0x5A (arbitrary non-zero pattern). The
     * game-side check is `bcmp(secret, all_zeros, 128) != 0`, so any non-zero
     * content passes. Daemon-side signature validation (if any) is a separate
     * concern — see Phase B3 backlog if this fails. */
    uint8_t fake_secret[128];
    memset(fake_secret, 0x5A, sizeof(fake_secret));

    /* Patch the cache.
     *
     * RE finding (B2-r2 fix): the ctor `FUN_0102d920` is called from
     * `FUN_0102a030` with param_4=0xffffffff, so +0xbc starts at 0xffffffff
     * → `FUN_0102e080` returns FALSE → `sceNpAsmClientGetNpTitleId` takes the
     * LAB_0102a38f branch (subsystem not ready) → checks ONLY +0xa4.
     *
     * Therefore: +0xa4=1 is the PRIMARY bypass. +0xa5/+0xa6 cover the
     * alternate branches if +0xbc later becomes 4 or 5 (sub-init updates). */
    bool ok_title = prw::proc_write((pid_t)game_pid, struct_va + 0x14, fake_title_id, 16);
    bool ok_secret = prw::proc_write((pid_t)game_pid, struct_va + 0x24, fake_secret, 128);
    uint8_t b1 = 1;
    bool ok_fa4 = prw::proc_write((pid_t)game_pid, struct_va + 0xa4, &b1, 1); /* externally set (LAB_0102a38f branch) */
    bool ok_fa5 = prw::proc_write((pid_t)game_pid, struct_va + 0xa5, &b1, 1); /* old SDK cache populated */
    bool ok_fa6 = prw::proc_write((pid_t)game_pid, struct_va + 0xa6, &b1, 1); /* new SDK cache populated */

    /* Post-verify: read flags back. */
    flag_a4 = flag_a5 = flag_a6 = 0xFF;
    prw::proc_read((pid_t)game_pid, struct_va + 0xa4, &flag_a4, 1);
    prw::proc_read((pid_t)game_pid, struct_va + 0xa5, &flag_a5, 1);
    prw::proc_read((pid_t)game_pid, struct_va + 0xa6, &flag_a6, 1);

    /* Also read back title_id to confirm write took. */
    char readback_title[17] = {0};
    prw::proc_read((pid_t)game_pid, struct_va + 0x14, readback_title, 16);

    phu_kstuff_ctrl_restore_after_op(resumed);

    klog_printf("[trophy] B2 inject: title='%.12s' (writes: t=%d s=%d a4=%d a5=%d a6=%d) "
                "POST-state: +0xa4=%u +0xa5=%u +0xa6=%u readback_title='%.12s'\n",
                fake_title_id, (int)ok_title, (int)ok_secret, (int)ok_fa4, (int)ok_fa5,
                (int)ok_fa6, flag_a4, flag_a5, flag_a6, readback_title);
    phu_diag_log("trophy B2 inject: tid=%s writes t=%d s=%d post a4=%u a5=%u a6=%u",
                 titleid ? titleid: "?", (int)ok_title, (int)ok_secret,
                 flag_a4, flag_a5, flag_a6);

    /* Success if data writes (title+secret) AND at least one flag write
     * succeeded. The 3 flag writes cover different code paths in
     * sceNpAsmClientGetNpTitleId:
     * - +0xa4=1: LAB_0102a38f branch (subsystem not ready — DEFAULT after
     * ctor which sets +0xbc=0xffffffff). This is the primary
     * bypass route on fresh game launch.
     * - +0xa5=1: old SDK subsystem-ready branch.
     * - +0xa6=1: new SDK subsystem-ready branch.
     * Requiring ALL flags = false negative if subsystem transitions ready
     * later but +0xa4 was the actual win route. */
    int b2_rc = (ok_title && ok_secret && (ok_fa4 || ok_fa5 || ok_fa6)) ? 0: -1;
    if (b2_rc != 0) {
        klog_printf("[trophy] B2 incomplete — skip B6 force-install\n");
        return b2_rc;
    }

    /* Phase B6 — now that B2 cache inject succeeded, the game's libSceNpManager
     * will accept any further Np call. Force RegisterContext via pt_call so the
     * daemon actually receives an install request (raw dumps never call this
     * on their own — that's why /user/trophy/conf/NPWR*_00/ is never created). */
    int b6_rc = phu_trophy_force_install_via_ptcall(game_pid, titleid);
    klog_printf("[trophy] B6 returned rc=%d (0=installed, +1=skipped, -1=failed)\n", b6_rc);

    /* r19.60 — post-install disk state check. After B6 (success or fail), dump
     * the on-disk trophy state so users sending PHUdiag.txt provide enough info
     * to identify "trophies don't appear in profile" without further RE. */
    do_post_install_diag(game_pid, titleid, b6_rc);

    return 0; /* B2 success is the main return — B6 result is informational. */
}

/* ============================================================================
 * Phase B6 — force trophy install via pt_call sequence.
 *
 * RATIONALE:
 * B1+B2+B3+B4 unblock the daemon to ACCEPT a register-context request from a
 * raw dump. But raw dumps (Astro Bot etc.) NEVER call sceNpTrophy2RegisterContext
 * themselves — fpkg games do that during their first-launch install flow which
 * raw dumps skip entirely. Therefore /user/trophy/conf/NPWR*_00/ is never
 * created and trophies don't appear in the profile.
 *
 * B6 forces the call from the game's own process via libNineS pt_call so the
 * daemon receives a legitimate-looking IPMI cmd 0x90016 from a process with
 * the right authid + sandbox context. This is the same approach etaHEN's
 * trophy unlocker uses internally.
 *
 * CALL SEQUENCE:
 * 1. CreateContext(&ctxId, commId, serviceId=0, options=0) → ctxId
 * 2. CreateHandle(&handleId) → handleId
 * 3. RegisterContext(ctxId, handleId, options=0) → TRIGGERS INSTALL
 * 4. DestroyHandle(handleId)
 * 5. DestroyContext(ctxId)
 *
 * The commId (SceNpCommunicationId = 16B: 9 char id + null + 2 char num
 * "_00" + 4 bytes pad) is parsed out of /user/app/<TID>/sce_sys/trophy2/npbind.dat
 * which is part of every dump's sce_sys metadata.
 * ============================================================================ */

/* npbind.dat layout (empirical RE 2026-05-13 + hex dump Astro Bot PPSA21564):
 * PS5 npbind.dat is fully Sony-AES-encrypted on disk. The 532-byte file has
 * a 16-byte binary header (e.g. d2 94 a0 18...) followed by AES-encrypted
 * commId + signature payload. Only SceShellCore can decrypt (Sony key
 * embedded in daemon). Cannot extract plain "NPWR*" commid client-side.
 *
 * This means B6's earlier "parse commId from offset 0x20" was based on a
 * wrong assumption (PS4 Trophy 1 had plaintext commid in npbind.dat; PS5
 * Trophy 2 encrypts everything). The good news: Trophy 2's
 * sceNpTrophy2CreateContext takes commId as INT (not pointer), and can
 * pass commId=0 — the daemon resolves the actual NPWR commid for the
 * foreground title from the encrypted file using its own decrypt path.
 *
 * So this function is now purely DIAGNOSTIC: verify file exists + readable +
 * log size & first bytes for future RE. Never blocks B6. */

/* ============================================================================
 * B7 — Path A: copy game's trophy files into daemon canonical path
 * ----------------------------------------------------------------------------
 * RE 2026-05-13 confirmed FUN_01a9e9f0 selects retail path
 * /system_data/priv/appmeta/<TID>/npbind.dat (BARE, no trophy2/ subdir)
 * for the trophy daemon's npbind read. fpkg installer (FUN_01311b50→01311f00)
 * writes this file during package install. RAW DUMPS skip this flow entirely,
 * so the daemon's open returns ENOENT and RegisterContext bails.
 *
 * B7 reproduces what the installer does: copy npbind.dat and trophy00.ucp
 * from game's read-only sce_sys/trophy2/ dir into the daemon's appmeta dir.
 * With B5_LNC + B3 + B4 + B7, the full chain succeeds end-to-end.
 *
 * Paths:
 * SRC: /user/app/<TID>/sce_sys/trophy2/{npbind.dat, trophy00.ucp}
 * DST: /system_data/priv/appmeta/<TID>/npbind.dat (BARE — canonical)
 * /system_data/priv/appmeta/<TID>/trophy2/npbind.dat (for FUN_012fda40 callers)
 * /system_data/priv/appmeta/<TID>/trophy2/trophy00.ucp
 *
 * Requires DEBUG_AUTHID (PHU probe has it). Idempotent — skip-if-exists.
 * ============================================================================ */
/* r17 — open declared as variadic locally to safely pass mode_t for O_CREAT.
 * r16 omitted the mode arg, causing files to be created with mode 000 — daemon
 * couldn't read them and RegisterContext returned 0x80553921. */
extern "C" int open(const char *path, int flags,...);

/* r18 — stat-skip helper: returns size in bytes of `path` (via lseek
 * SEEK_END trick) or -1 if unreadable / doesn't exist. SEEK_END constant on
 * FreeBSD = 2. Used by b7_copy_file to skip the 16 MB trophy00.ucp re-copy
 * when daemon already has the file. */
static long b7_file_size(const char *path) {
    int fd = open(path, 0 /* O_RDONLY */);
    if (fd < 0) return -1; /* EACCES (mode 000 from r16) or ENOENT */
    long sz = lseek(fd, 0, 2 /* SEEK_END */);
    close(fd);
    return sz;
}

static int b7_copy_file(const char *src, const char *dst) {
    /* r18 stat-skip: compare dst size to src size. If equal → file already
     * copied (idempotent). If smaller → partial copy (interrupted) → re-copy.
     * If dst doesn't exist OR is unreadable (mode 000 from r16 bug) → re-copy
     * with mode 0666. This handles all 3 cases: fresh, partial, mode-bug. */
    long src_sz = b7_file_size(src);
    long dst_sz = b7_file_size(dst);
    if (src_sz > 0 && dst_sz == src_sz) {
        klog_printf("[trophy] B7 skip %s (already present, %ld bytes match src)\n",
                    dst, dst_sz);
        return 0;
    }
    if (dst_sz > 0 && dst_sz != src_sz) {
        klog_printf("[trophy] B7 size mismatch %s: dst=%ld src=%ld — re-copy\n",
                    dst, dst_sz, src_sz);
    }

    int sfd = open(src, 0 /* O_RDONLY */);
    if (sfd < 0) {
        klog_printf("[trophy] B7 open src '%s' FAIL\n", src);
        return -1;
    }
    /* O_WRONLY|O_CREAT|O_TRUNC = 0x602 (BSD-style) + mode 0666 (rw-rw-rw-). */
    int dfd = open(dst, 0x602, 0666);
    if (dfd < 0) {
        close(sfd);
        klog_printf("[trophy] B7 open dst '%s' FAIL\n", dst);
        return -1;
    }
    char buf[8192];
    long total = 0;
    long n;
    while ((n = read(sfd, buf, sizeof(buf))) > 0) {
        long w = write(dfd, buf, (size_t)n);
        if (w != n) {
            klog_printf("[trophy] B7 short write %s (read %ld wrote %ld)\n", dst, n, w);
            close(sfd); close(dfd);
            return -1;
        }
        total += w;
    }
    close(sfd);
    close(dfd);

    /* Defensive: enforce perms 0666 in case the file already existed with
     * wrong mode (idempotent re-runs of r16). chmod doesn't change owner. */
    int cm = chmod(dst, 0666);
    klog_printf("[trophy] B7 copied %s -> %s (%ld bytes) chmod rc=%d\n",
                src, dst, total, cm);
    return 0;
}

/* r18 — extract NPWR<id>_00 from npbind.dat plaintext TLV 0x10. The commId is
 * NOT encrypted (RE confirmed 2026-05-13 via RE). Allows PHU
 * to know in advance which NPWR dir to expect in /user/trophy2/nobackup/conf/.
 *
 * Path: /user/app/<TID>/sce_sys/trophy2/npbind.dat (PS5 native PPSA or PPSB).
 * PS4 BC games filtered out upstream by trophy_is_ps5_native. */
static int b7_extract_npwr_from_npbind(const char *titleid, char out_npwr[16]) {
    if (!titleid || !titleid[0]) return -1;
    char path[256];
    snprintf(path, sizeof(path),
             "/user/app/%s/sce_sys/trophy2/npbind.dat", titleid);
    int fd = open(path, 0);
    if (fd < 0) return -1;

    uint8_t buf[1024]; /* npbind.dat is ~532 bytes; 1024 covers it */
    long n = read(fd, buf, sizeof(buf));
    close(fd);
    if (n < 0x90) return -1;

    /* Magic check: 0xD294A018 (big-endian per RE). */
    if (buf[0] != 0xd2 || buf[1] != 0x94 || buf[2] != 0xa0 || buf[3] != 0x18) {
        return -1;
    }

    /* TLVs start after 0x80-byte header.
     * Each TLV: u16_be tag, u16_be len, payload[len].
     * r18 audit I4 fix: add bound check on len to prevent jumping past `n`
     * with no further parse (= silent miss of the 0x0010 tag if it follows). */
    long off = 0x80;
    while (off + 4 <= n) {
        uint16_t tag = (uint16_t)((buf[off] << 8) | buf[off+1]);
        uint16_t len = (uint16_t)((buf[off+2] << 8) | buf[off+3]);
        if (tag == 0x0000) break; /* end-of-list */
        /* Bound check: payload must fit in remaining buffer. */
        if ((long)len > n - off - 4) break; /* malformed or truncated */
        if (tag == 0x0010 && len == 12) {
            /* Found NpCommId — 12 chars "NPWRxxxxx_00" plaintext. */
            memcpy(out_npwr, &buf[off+4], 12);
            out_npwr[12] = '\0';
            for (int i = 13; i < 16; i++) out_npwr[i] = 0;
            return 0;
        }
        off += 4 + (long)len;
    }
    return -1;
}

/* ============================================================================
 * r19.60 — Post-install disk state dump
 * ----------------------------------------------------------------------------
 * Called after B6 force-install. Logs the on-disk state of trophy storage so
 * users sending PHUdiag.txt can be diagnosed for "trophies don't appear in
 * profile" without needing a klog stream or further RE.
 *
 * Checks:
 * - B6 rc with human-readable interpretation
 * - NPWR extracted from titleid's npbind.dat
 * - TROPHY.UCP existence at canonical path /user/trophy2/nobackup/conf/<NPWR>/
 * AND legacy path /user/trophy/conf/<NPWR>/
 * - B7 destination files in /system_data/priv/appmeta/<TID>/trophy2/
 *
 * The signature of each failure mode is:
 * - B6=0 + TROPHY.UCP missing -> daemon refused commit (= B5_auth missing,
 * NpAsmClient cache rollback by Sony cleanup, or sealed key mismatch)
 * - B6=0 + TROPHY.UCP present + profile shows nothing -> UpdateSummaryFile
 * DELETE path fired (= 4.03 IsDeprecatedVersion bug, needs trio B20+B21+B22)
 * - B6=-1 + TROPHY.UCP missing -> chain bailed (check earlier diag lines)
 * - B6=-2 + TROPHY.UCP missing -> libSceNpTrophy2 timeout (game not ready)
 * -> wait for game's NATURAL register call (= primary path)
 * - appmeta files missing -> B7 didn't run (= check earlier B7 errors)
 * ============================================================================ */
static void do_post_install_diag(int game_pid, const char *titleid, int b6_rc) {
    if (!titleid || !titleid[0]) return;
    /* r19.60 opt-in: default off — only dump disk state when explicitly enabled
     * via cfg `trophy_post_install_diag = 1`. Keeps production runtime clean. */
    if (!g_phu_cfg.trophy_post_install_diag) return;

    /* Step 1 — B6 rc interpretation */
    const char *rc_meaning;
    switch (b6_rc) {
        case 0: rc_meaning = "OK installed"; break;
        case 1: rc_meaning = "skipped (already done)"; break;
        case -1: rc_meaning = "FAILED (B6 chain bailed)"; break;
        case -2: rc_meaning = "skipped (lib not loaded)"; break;
        default: rc_meaning = "unknown"; break;
    }
    klog_printf("[trophy] post-install: pid=%d tid=%s B6_rc=%d (%s)\n",
                game_pid, titleid, b6_rc, rc_meaning);
    phu_diag_log("trophy post-install: tid=%s B6_rc=%d (%s)",
                titleid, b6_rc, rc_meaning);

    /* Step 2 — extract NPWR from titleid's npbind.dat (= read source) */
    char npwr[16] = {0};
    int npwr_ok = (b7_extract_npwr_from_npbind(titleid, npwr) == 0);
    if (npwr_ok) {
        klog_printf("[trophy] post-install: NPWR='%s' (from /user/app/%s/sce_sys/trophy2/npbind.dat)\n",
                    npwr, titleid);
        phu_diag_log("trophy post-install: NPWR=%s", npwr);
    } else {
        klog_printf("[trophy] post-install: NPWR extract FAIL — game's npbind.dat unreadable\n");
        phu_diag_log("trophy post-install: NPWR extract FAIL (npbind unreadable)");
        return; /* without NPWR, can't check storage paths */
    }

    /* Step 3 — check TROPHY.UCP (= daemon storage commit confirmation) */
    char path_nobackup[256], path_user[256];
    snprintf(path_nobackup, sizeof(path_nobackup),
             "/user/trophy2/nobackup/conf/%s/TROPHY.UCP", npwr);
    snprintf(path_user, sizeof(path_user),
             "/user/trophy/conf/%s/TROPHY.UCP", npwr);
    long sz_nobackup = b7_file_size(path_nobackup);
    long sz_user = b7_file_size(path_user);
    klog_printf("[trophy] post-install: TROPHY.UCP nobackup=%ld bytes user=%ld bytes\n",
                sz_nobackup, sz_user);
    phu_diag_log("trophy post-install: TROPHY.UCP nobackup=%ld user=%ld",
                sz_nobackup, sz_user);

    /* Step 4 — check B7 destination files (= daemon read source for Cronos/pre-Cronos) */
    char appmeta_np[256], appmeta_trp[256], appmeta_bare[256];
    snprintf(appmeta_np, sizeof(appmeta_np),
             "/system_data/priv/appmeta/%s/trophy2/npbind.dat", titleid);
    snprintf(appmeta_trp, sizeof(appmeta_trp),
             "/system_data/priv/appmeta/%s/trophy2/trophy00.ucp", titleid);
    snprintf(appmeta_bare, sizeof(appmeta_bare),
             "/system_data/priv/appmeta/%s/npbind.dat", titleid);
    long sz_np = b7_file_size(appmeta_np);
    long sz_trp = b7_file_size(appmeta_trp);
    long sz_bare = b7_file_size(appmeta_bare);
    klog_printf("[trophy] post-install: appmeta trophy2/npbind=%ld trophy00=%ld bare-npbind=%ld\n",
                sz_np, sz_trp, sz_bare);
    phu_diag_log("trophy post-install: appmeta np=%ld trp=%ld bare=%ld",
                sz_np, sz_trp, sz_bare);

    /* Step 5 — failure-mode hint (= diagnostic guidance for user reports) */
    bool commit_ok = (sz_nobackup > 0) || (sz_user > 0);
    if (b6_rc == 0 && !commit_ok) {
        klog_printf("[trophy] post-install HINT: B6 rc=0 but TROPHY.UCP MISSING — "
                    "daemon refused commit (B5_auth missing / NpAsmClient cache rollback / sealed key)\n");
        phu_diag_log("trophy POST-HINT: B6=OK but TROPHY.UCP MISSING — daemon refused");
    } else if (b6_rc == 0 && commit_ok) {
        klog_printf("[trophy] post-install HINT: B6 rc=0 + TROPHY.UCP present — "
                    "if profile shows nothing, UpdateSummaryFile DELETE path fired "
                    "(4.03 IsDeprecatedVersion bug — set cfg trophy_summary_bypass_enabled=1)\n");
        phu_diag_log("trophy POST-HINT: commit OK, if profile empty -> trio fix needed");
    } else if (b6_rc == -2 && !commit_ok) {
        klog_printf("[trophy] post-install HINT: B6 timeout (lib not loaded) — "
                    "wait for game's NATURAL sceNpTrophy2RegisterContext call\n");
        phu_diag_log("trophy POST-HINT: B6 timeout, awaiting natural register");
    } else if (b6_rc == -1) {
        klog_printf("[trophy] post-install HINT: B6 chain bailed — check earlier diag for "
                    "B2 / B5_auth / B7 fail markers\n");
        phu_diag_log("trophy POST-HINT: B6 failed, check earlier markers");
    }
}

/* r18 — cross-session install detection.
 * After daemon installs trophies, it creates /user/trophy2/nobackup/conf/<NPWR>/
 * with TROPHY.UCP. Can detect prior installs by:
 * 1. Extract NPWR from game's npbind.dat (plaintext TLV 0x10)
 * 2. Stat /user/trophy2/nobackup/conf/<NPWR>/TROPHY.UCP — readable + non-empty
 *
 * If both pass → install was done previously → skip ALL of B2+B7+B6 to save
 * I/O (16 MB+ files, pt_attach overhead, 5s libSceNpTrophy2 poll). */
static bool phu_trophy_already_installed(const char *titleid) {
    char npwr[16] = {0};
    if (b7_extract_npwr_from_npbind(titleid, npwr) != 0) {
        return false; /* can't determine — assume not installed, run full chain */
    }
    char path[256];
    snprintf(path, sizeof(path),
             "/user/trophy2/nobackup/conf/%.12s/TROPHY.UCP", npwr);
    /* r18 audit I1 fix: check actual file size, not just "1 byte readable".
     * A partial copy (daemon interrupted mid-install) would have a small TROPHY.UCP
     * but daemon's RegisterContext would fail on read. Real TROPHY.UCP files are
     * typically >= 1 MB (Astro Bot = 16 MB, smaller games still > 100 KB).
     * Require >= 1024 bytes as minimum sanity threshold. */
    long sz = b7_file_size(path);
    if (sz < 1024) {
        if (sz < 0) {
            klog_printf("[trophy] B7 detect: %s NPWR=%s install MISSING (open fail) — "
                        "run full chain\n", titleid, npwr);
        } else {
            klog_printf("[trophy] B7 detect: %s NPWR=%s file too small (sz=%ld) — "
                        "partial install ? — run full chain\n", titleid, npwr, sz);
        }
        return false;
    }
    klog_printf("[trophy] B7 detect: %s NPWR=%s already installed (%ld bytes) @ %s — "
                "SKIP full chain\n", titleid, npwr, sz, path);
    phu_diag_log("trophy B7 detect: tid=%s npwr=%s sz=%ld already-installed",
                 titleid, npwr, sz);
    return true;
}

/* ============================================================================
 * r19.61 — Per-user already-installed check
 * ----------------------------------------------------------------------------
 * Empirical RE 2026-05-21 via FTP scan on fw 9.40 (2 PSN accounts) confirmed
 * Sony's 3-level trophy storage architecture:
 *
 * LEVEL 1 — SPONSOR (per-NPWR GLOBAL)
 * /user/trophy2/nobackup/conf/<NPWR>/TROPHY.UCP (signed master, 5-95 MB)
 *
 * LEVEL 2 — STATE (per-NPWR per-USER)
 * /user/home/<uid_hex>/trophy2/nobackup/data/<NPWR>/TRPTITLE.DAT (12-56 KB)
 *
 * LEVEL 3 — SUMMARY (per-USER aggregate)
 * /user/home/<uid_hex>/trophy/data/sce_trop/trpsummary.dat (JSON, ~76 B)
 *
 * The legacy `phu_trophy_already_installed` checks LEVEL 1 (sponsor) — which is
 * GLOBAL and does NOT distinguish per-user. Result: if user1 has installed
 * the trophy, the check returns true for user2 too → user2's chain skipped →
 * user2 sees nothing.
 *
 * This per-user check inspects LEVEL 2 (state) which is isolated per PSN account.
 * Returns true only if the SPECIFIC user has the NPWR registered.
 *
 * Effects:
 * - First-time user for this NPWR → returns false → fire B7+B2+B6 (register)
 * - Returning user with state present → returns true → skip B7+B2+B6
 * → Sony's natural chain reads the historical state → trophies preserved
 *
 * Fixes both:
 * - Multi-user (user2 isolated from user1's install)
 * - Historical trophies (existing user's state not corrupted by re-inject)
 * ============================================================================ */
static bool phu_trophy_already_installed_for_user(const char *titleid, int uid) {
    if (uid <= 0) return false; /* no valid user → run full chain */
    char npwr[16] = {0};
    if (b7_extract_npwr_from_npbind(titleid, npwr) != 0) {
        return false;
    }
    /* Sony PS5 uid format = 8-char hex (e.g. 179a0cd8). Use %08x for padding
     * in case uid < 0x10000000 (would format to less than 8 chars otherwise). */
    char path[256];
    snprintf(path, sizeof(path),
             "/user/home/%08x/trophy2/nobackup/data/%.12s/TRPTITLE.DAT",
             (unsigned int)uid, npwr);
    long sz = b7_file_size(path);
    if (sz > 0) {
        klog_printf("[trophy] B7 per-user detect: tid=%s uid=%08x NPWR=%s TRPTITLE.DAT=%ld B "
                    "— user state EXISTS → skip B7+B2+B6 (state preserved)\n",
                    titleid, (unsigned int)uid, npwr, sz);
        phu_diag_log("trophy B7 per-user: tid=%s uid=%08x npwr=%s state-exists sz=%ld",
                     titleid, (unsigned int)uid, npwr, sz);
        return true;
    }
    /* Also check Trophy 1 fallback (PS4 BC games — rare for PHU but safe) */
    snprintf(path, sizeof(path),
             "/user/home/%08x/trophy/data/%.12s/trophy.img",
             (unsigned int)uid, npwr);
    sz = b7_file_size(path);
    if (sz > 0) {
        klog_printf("[trophy] B7 per-user detect: tid=%s uid=%08x NPWR=%s Trophy1 trophy.img=%ld B "
                    "— user state EXISTS (PS4 BC path) → skip\n",
                    titleid, (unsigned int)uid, npwr, sz);
        phu_diag_log("trophy B7 per-user trophy1: tid=%s uid=%08x sz=%ld",
                     titleid, (unsigned int)uid, sz);
        return true;
    }
    klog_printf("[trophy] B7 per-user detect: tid=%s uid=%08x NPWR=%s — user state NOT FOUND "
                "→ run full chain (first time for this user)\n",
                titleid, (unsigned int)uid, npwr);
    phu_diag_log("trophy B7 per-user: tid=%s uid=%08x npwr=%s NOT-FOUND",
                 titleid, (unsigned int)uid, npwr);
    return false;
}

/* Returns count of files copied (or skipped-because-exists), -1 on hard fail. */
static int phu_trophy_setup_appmeta(const char *titleid) {
    if (!titleid || !titleid[0]) return -1;

    char appmeta_dir[256];
    char appmeta_trophy2_dir[300];
    char gametemp_dir[256];
    char gametemp_trophy2_dir[300];
    char src_npbind[256], dst_npbind[300], dst_trophy2_npbind[320];
    char dst_gametemp_npbind[300], dst_gametemp_trophy2_npbind[320];
    char src_ucp[256], dst_trophy2_ucp[320], dst_gametemp_trophy2_ucp[320];

    snprintf(appmeta_dir, sizeof(appmeta_dir),
             "/system_data/priv/appmeta/%s", titleid);
    snprintf(appmeta_trophy2_dir, sizeof(appmeta_trophy2_dir),
             "/system_data/priv/appmeta/%s/trophy2", titleid);
    /* r19.10 — 10.01 daemon reads npbind.dat from NEW PATH when
     * sceKernelIsCronos==1 (PS5). RE'd via FUN_01a96940 (SceShellCore 10.01):
     * "/system_data/game/temp/<TID>/npbind.dat"
     * The OLD path /system_data/priv/appmeta/ is the PS4-Cronos fallback only.
     * Write to BOTH paths so any fw + any daemon code path resolves cleanly.
     * 9.40 + 7.61 daemon ignores game/temp/ (no xref) → zero impact. */
    snprintf(gametemp_dir, sizeof(gametemp_dir),
             "/system_data/game/temp/%s", titleid);
    snprintf(gametemp_trophy2_dir, sizeof(gametemp_trophy2_dir),
             "/system_data/game/temp/%s/trophy2", titleid);
    snprintf(src_npbind, sizeof(src_npbind),
             "/user/app/%s/sce_sys/trophy2/npbind.dat", titleid);
    snprintf(dst_npbind, sizeof(dst_npbind),
             "/system_data/priv/appmeta/%s/npbind.dat", titleid);
    snprintf(dst_trophy2_npbind, sizeof(dst_trophy2_npbind),
             "/system_data/priv/appmeta/%s/trophy2/npbind.dat", titleid);
    snprintf(dst_gametemp_npbind, sizeof(dst_gametemp_npbind),
             "/system_data/game/temp/%s/npbind.dat", titleid);
    snprintf(dst_gametemp_trophy2_npbind, sizeof(dst_gametemp_trophy2_npbind),
             "/system_data/game/temp/%s/trophy2/npbind.dat", titleid);
    snprintf(src_ucp, sizeof(src_ucp),
             "/user/app/%s/sce_sys/trophy2/trophy00.ucp", titleid);
    snprintf(dst_trophy2_ucp, sizeof(dst_trophy2_ucp),
             "/system_data/priv/appmeta/%s/trophy2/trophy00.ucp", titleid);
    snprintf(dst_gametemp_trophy2_ucp, sizeof(dst_gametemp_trophy2_ucp),
             "/system_data/game/temp/%s/trophy2/trophy00.ucp", titleid);

    /* Verify SRC exists. If not, game has no trophy package → skip silently. */
    int sfd = open(src_npbind, 0);
    if (sfd < 0) {
        klog_printf("[trophy] B7 src '%s' not found — game has no trophies, skip\n",
                    src_npbind);
        return 0;
    }
    close(sfd);

    /* Step 1: ensure appmeta dir exists (Sony installer creates this normally).
     * For Astro Bot observed it exists already (drwxrwxrwx). For other titles it
     * might not. mkdir returns -1 with errno=EEXIST if already there — fine. */
    int mk = mkdir(appmeta_dir, 0777);
    klog_printf("[trophy] B7 mkdir '%s' rc=%d (EEXIST=ok)\n", appmeta_dir, mk);

    /* Step 2: ensure appmeta/trophy2/ subdir exists. */
    mk = mkdir(appmeta_trophy2_dir, 0777);
    klog_printf("[trophy] B7 mkdir '%s' rc=%d (EEXIST=ok)\n", appmeta_trophy2_dir, mk);

    /* Step 3: copy npbind.dat to BARE canonical path (legacy). */
    int copied = 0;
    if (b7_copy_file(src_npbind, dst_npbind) == 0) copied++;
    /* Step 4: copy npbind.dat to trophy2/ subdir mirror (FUN_012fda40 callers). */
    if (b7_copy_file(src_npbind, dst_trophy2_npbind) == 0) copied++;
    /* Step 5: copy trophy00.ucp to trophy2/ subdir (some daemon paths need it). */
    if (b7_copy_file(src_ucp, dst_trophy2_ucp) == 0) copied++;

    /* r19.58 — B7 Cronos extra copy retired. 10.01 used to additionally write
     * to /system_data/game/temp/<TID>/ but that path is handled by Sony's
     * AppSubcontainerPrepareNpForCronos auto-prepare. 10.00 works clean
     * without this extra I/O. */
    klog_printf("[trophy] B7 appmeta setup done: %d/3 files copied for %s\n",
                copied, titleid);
    phu_diag_log("trophy B7 appmeta: tid=%s files=%d/3", titleid, copied);
    return copied;
}

static int b6_diag_check_npbind(const char *titleid) {
    if (!titleid || !titleid[0]) return -1;

    char path[256];
    snprintf(path, sizeof(path),
             "/user/app/%s/sce_sys/trophy2/npbind.dat", titleid);

    int fd = open(path, 0 /* O_RDONLY */);
    bool ps4_fallback = false;
    if (fd < 0) {
        snprintf(path, sizeof(path),
                 "/user/app/%s/sce_sys/trophy/npbind.dat", titleid);
        fd = open(path, 0);
        ps4_fallback = (fd >= 0);
        if (fd < 0) {
            klog_printf("[trophy] B6 npbind.dat NOT found for %s "
                        "(no trophy2/ nor trophy/) — game has no trophies, skip\n",
                        titleid);
            return -1;
        }
    }

    uint8_t hdr[32] = {0};
    long n = read(fd, hdr, sizeof(hdr));
    close(fd);
    if (n <= 0) {
        klog_printf("[trophy] B6 npbind.dat read FAIL n=%ld — abort\n", n);
        return -1;
    }

    /* Log empirical evidence: file format identifies version + encryption. */
    klog_printf("[trophy] B6 npbind.dat found at '%s' (%s) — first 16 bytes: "
                "%02x %02x %02x %02x %02x %02x %02x %02x "
                "%02x %02x %02x %02x %02x %02x %02x %02x "
                "(file is Sony-AES-encrypted; daemon-side decrypt via B3)\n",
                path, ps4_fallback ? "trophy/": "trophy2/",
                hdr[0], hdr[1], hdr[2], hdr[3], hdr[4], hdr[5], hdr[6], hdr[7],
                hdr[8], hdr[9], hdr[10], hdr[11], hdr[12], hdr[13], hdr[14], hdr[15]);
    phu_diag_log("trophy B6 npbind ok tid=%s hdr=%02x%02x%02x%02x",
                 titleid, hdr[0], hdr[1], hdr[2], hdr[3]);
    return 0;
}

extern "C" int phu_trophy_force_install_via_ptcall(int game_pid, const char *titleid) {
    if (!g_phu_cfg.trophy_unlock_enabled) return 1;
    if (!g_phu_cfg.trophy_force_install_enabled) return 1;
    if (game_pid <= 0 || !titleid) return -1;
    if (!trophy_titleid_in_whitelist(titleid)) return 1;
    /* r19.4 — per-fw lookup once at top, used in B6 r15 reuse path below. */
    const phu_trophy_fw_offsets_t *e = get_fw_offsets;
    if (!e) {
        klog_printf("[trophy] B6 fw unsupported — skip force-install\n");
        return -1;
    }

    /* Once-per-session gate — apply_per_game fires every game-detect cycle.
     * Repeat B6 invocations on the same title would re-trigger Sony notif +
     * hit the daemon with already-registered context (silent error). */
    /* r19.48 Lestat multi-user fix: DISABLED session cache. Previously this
     * blocked re-running B6 for the same titleid in the same session, which
     * also blocked the multi-user case (user1 plays Stray → cache → user2
     * plays Stray → B6 skip → user2 gets no trophies). Since B6 is per-user
     * and idempotent for already-registered users (~100-500ms), the cache
     * was a minor perf optimization that broke multi-user support. Removed.
     *
     * Original concern (= "repeated Sony notif") mitigated by toastOverwriteType
     * dedup in sceNotificationSend (only LAST notif visible). */
    (void)g_b6_done_titleid; /* kept for ABI/log compat, no longer used as cache */

    klog_printf("[trophy] B6 force-install start: pid=%d tid=%s\n", game_pid, titleid);
    phu_diag_log("trophy B6 start: pid=%d tid=%s", game_pid, titleid);

    /* 1. Diagnostic check: npbind.dat presence. The file is Sony-AES-encrypted
     * so CAN'T extract plaintext NPWR commid client-side; the daemon does
     * that with its embedded Sony key (B3 patch makes it tolerate any digest).
     * Just confirm the file exists (= game has trophies metadata, can register).
     * If file missing → game has no trophies, skip cleanly. */
    if (b6_diag_check_npbind(titleid) != 0) {
        return 1; /* no trophies for this game — not an error */
    }

    /* 2. Confirm libSceNpTrophy2.sprx is loaded in the game. Poll up to 5s
     * (same window as B2's libSceNpManager poll) since trophy lib may load
     * a few seconds after game start (NpToolkit init). If still absent after
     * 5s, return +1 (skipped, not -1) — game probably has no trophy support.
     * TODO r12: pt_call sceSysmoduleLoadModule(0x110) to force-load it. */
    uint32_t tr2_handle = 0;
    int tr2_retry;
    for (tr2_retry = 0; tr2_retry < 10; tr2_retry++) {
        if (kernel_dynlib_handle(game_pid, "libSceNpTrophy2.sprx", &tr2_handle) == 0
            && tr2_handle != 0) {
            break;
        }
        tr2_handle = 0;
        usleep(500000);
    }
    if (tr2_handle == 0) {
        klog_printf("[trophy] B6 libSceNpTrophy2.sprx not loaded in pid=%d after 5s — "
                    "game has no trophy support, skip cleanly\n", game_pid);
        phu_diag_log("trophy B6 libSceNpTrophy2 not loaded after 5s pid=%d", game_pid);
        return 1; /* skipped — not an error */
    }
    klog_printf("[trophy] B6 libSceNpTrophy2 loaded (handle=%u after %d retries)\n",
                tr2_handle, tr2_retry);

    /* 3. Resolve the 5 sceNpTrophy2 exports. Use the public names — Sony's
     * runtime linker resolves them through the SPRX export table.
     * RE confirms these are the user-facing IPMI marshallers. */
    intptr_t fn_create_ctx = kernel_dynlib_dlsym(game_pid, tr2_handle, "sceNpTrophy2CreateContext");
    intptr_t fn_create_handle = kernel_dynlib_dlsym(game_pid, tr2_handle, "sceNpTrophy2CreateHandle");
    intptr_t fn_register_ctx = kernel_dynlib_dlsym(game_pid, tr2_handle, "sceNpTrophy2RegisterContext");
    intptr_t fn_destroy_handle = kernel_dynlib_dlsym(game_pid, tr2_handle, "sceNpTrophy2DestroyHandle");
    intptr_t fn_destroy_ctx = kernel_dynlib_dlsym(game_pid, tr2_handle, "sceNpTrophy2DestroyContext");
    /* r19.9 — DebugUnlockTrophy for 10.01 where RegisterContext path A+B are dead.
     * Resolved here, used in DebugUnlock loop after RegisterContext attempt. */
    intptr_t fn_debug_unlock = kernel_dynlib_dlsym(game_pid, tr2_handle, "sceNpTrophy2SystemDebugUnlockTrophy");

    klog_printf("[trophy] B6 dlsym: CreateCtx=0x%lx CreateHnd=0x%lx Register=0x%lx "
                "DestroyHnd=0x%lx DestroyCtx=0x%lx\n",
                (uintptr_t)fn_create_ctx, (uintptr_t)fn_create_handle,
                (uintptr_t)fn_register_ctx, (uintptr_t)fn_destroy_handle,
                (uintptr_t)fn_destroy_ctx);

    if (fn_create_ctx <= 0 || fn_create_handle <= 0 || fn_register_ctx <= 0) {
        klog_printf("[trophy] B6 critical sym resolve FAILED (Create/Register missing) — abort\n");
        phu_diag_log("trophy B6 dlsym critical fail pid=%d", game_pid);
        return -1;
    }

    /* 3.5 r14 — Resolve sceUserServiceGetForegroundUser in libSceUserService.sprx.
     * Critical: CreateContext arg2 is user_id (NOT commId as r13 assumed).
     * RE FUN_01cc8d00 confirms: sce::np::User::GetUser(arg2) failure
     * returns 0x80553917 USER_NOT_FOUND, which is what observed with arg2=0 in r13.
     * libSceUserService.sprx is loaded in essentially every game (account info,
     * pad input, save data all need it). Brief poll for race safety.
     *
     * r19.12 — Beta tester reported 0x80960002 NO_EVENT on foreground user when
     * account is "offact"-activated but not signed-in via PS button. Resolve 3
     * fallback APIs: GetForegroundUser → GetInitialUser → GetLoginUserIdList.
     * Any non-zero uid found in any of these works for CreateContext. */
    uint32_t usr_handle = 0;
    intptr_t fn_get_fg_user = 0;
    intptr_t fn_get_initial_user = 0;
    intptr_t fn_get_user_list = 0;
    uint32_t npmgr_handle = 0; /* r19.13 — hoisted before pt_mmap goto */
    intptr_t fn_np_get_user_list = 0; /* r19.13 — hoisted before pt_mmap goto */
    for (int us_retry = 0; us_retry < 6; us_retry++) { /* 3s max */
        if (kernel_dynlib_handle(game_pid, "libSceUserService.sprx", &usr_handle) == 0
            && usr_handle != 0) {
            break;
        }
        usr_handle = 0;
        usleep(500000);
    }
    if (usr_handle != 0) {
        fn_get_fg_user = kernel_dynlib_dlsym(game_pid, usr_handle,
                                             "sceUserServiceGetForegroundUser");
        /* r19.12 fallback A: Initial user (= user who was active at console boot). */
        fn_get_initial_user = kernel_dynlib_dlsym(game_pid, usr_handle,
                                                  "sceUserServiceGetInitialUser");
        /* r19.12 fallback B: list of logged-in users. */
        fn_get_user_list = kernel_dynlib_dlsym(game_pid, usr_handle,
                                                "sceUserServiceGetLoginUserIdList");
    }
    /* r19.13 — sceNpUserGetUserIdList from libSceNpManager.sprx (offline-friendly,
     * daemon-native NP user list). Resolve BEFORE pt_mmap goto label. */
    for (int retry = 0; retry < 4; retry++) {
        if (kernel_dynlib_handle(game_pid, "libSceNpManager.sprx", &npmgr_handle) == 0
            && npmgr_handle != 0) break;
        npmgr_handle = 0;
        usleep(500000);
    }
    if (npmgr_handle != 0) {
        fn_np_get_user_list = kernel_dynlib_dlsym(game_pid, npmgr_handle,
                                                   "sceNpUserGetUserIdList");
    }
    klog_printf("[trophy] B6 libSceUserService handle=%u fg=0x%lx initial=0x%lx list=0x%lx\n",
                usr_handle, (uintptr_t)fn_get_fg_user,
                (uintptr_t)fn_get_initial_user, (uintptr_t)fn_get_user_list);
    klog_printf("[trophy] B6 libSceNpManager handle=%u sceNpUserGetUserIdList=0x%lx\n",
                npmgr_handle, (uintptr_t)fn_np_get_user_list);
    /* Non-fatal if missing — fall back to user_id=1 (PS5 primary user
     * default). The runtime error code from CreateContext will indicate if
     * that's good enough. */

    /* 4. pt_attach the game. */
    int rc_attach = pt_attach(game_pid);
    if (rc_attach < 0) {
        klog_printf("[trophy] B6 pt_attach pid=%d FAIL rc=%d — abort\n", game_pid, rc_attach);
        phu_diag_log("trophy B6 pt_attach fail rc=%d", rc_attach);
        return -1;
    }
    klog_printf("[trophy] B6 pt_attach OK pid=%d\n", game_pid);

    int final_rc = -1;
    /* r14 user_id: declared up-front (before any `goto`) because C++ forbids
     * jumping over an initialized variable into its scope. Default = 1 (PS5
     * primary user). Filled below from sceUserServiceGetForegroundUser. */
    int32_t user_id = 1;

    /* 5. pt_mmap a scratch buffer in game AS for the commId + 2 out-IDs.
     * Layout: [0..15]=commId [16..19]=ctxId [20..23]=handleId */
    intptr_t scratch_va = pt_mmap(game_pid, 0, 4096,
                                  PROT_READ | PROT_WRITE,
                                  MAP_PRIVATE | MAP_ANON, -1, 0);
    if (scratch_va == (intptr_t)-1 || scratch_va == 0) {
        klog_printf("[trophy] B6 pt_mmap scratch FAILED rc=0x%lx — abort\n", (uintptr_t)scratch_va);
        phu_diag_log("trophy B6 pt_mmap fail");
        goto detach;
    }
    klog_printf("[trophy] B6 scratch buf @ 0x%lx (game AS)\n", (uintptr_t)scratch_va);

    /* r14 — Resolve user_id via sceUserServiceGetForegroundUser INSIDE the game
     * process. RE corrected r13's mistake: CreateContext arg2 is a
     * sceUserService user_id (not a commId int). Without a valid user_id, the
     * daemon's sce::np::User::GetUser(user_id) returns 0x80553917 — exactly the
     * error r13 hit.
     *
     * r19.57 REORDERED PRIORITY (user diag 2026-05-20):
     * Previously r19.17 put /user/home/ FS scan as PRIMARY, which selected the
     * first numeric directory it found (often a stale user_id like 179 from a
     * deleted account). On consoles with multiple users where the current
     * foreground user differs from the lowest-numbered /user/home/ entry, this
     * caused B6 CreateContext to fail with 0x80553917 USER_NOT_FOUND because
     * the daemon's sce::np::User::GetUser rejected the stale uid. User report:
     * "avant ça trouvait mon user directement" — confirms GetForegroundUser
     * was the working pre-r19.17 path.
     *
     * NEW priority order:
     * 1. sceUserServiceGetForegroundUser → the ACTIVELY logged-in user
     * (authoritative for the daemon's User::GetUser check) (PRIMARY)
     * 2. sceNpUserGetUserIdList[0] → NP-aware list (offline-friendly)
     * 3. sceUserServiceGetInitialUser → init time user
     * 4. /user/home/ FS scan → last-ditch fallback for orphan installs
     *
     * user_id var declared above (hoisted to avoid goto-over-init C++ error). */

    /* r19.57 PRIMARY — Query sceUserServiceGetForegroundUser from
     * the PROBE PROCESS directly (not via pt_call into the game). Reason:
     * runtime diag user2 launch 2026-05-20 showed that when a game JUST
     * started, its libSceUserService has NOT yet been initialized → all
     * pt_call queries (GetForegroundUser, GetInitialUser, GetLoginUserIdList)
     * return 0x80960002 = SCE_USER_SERVICE_ERROR_NOT_INITIALIZED → fallback
     * to /user/home/ FS scan picks stale uid → CreateContext 0x80553917.
     *
     * The probe has its OWN libSceUserService linked + initialized (used by
     * phu_stats.c for the FPS overlay). Querying directly from probe context
     * always works because sceUserServiceInitialize was called at probe boot.
     *
     * This bypasses the game's init timing issue entirely. */
    /* r19.67 — REVERTED to r17-style user_id resolution as PRIMARY.
     *
     * Hypothesis confirmed (2026-05-22 runtime test 9.40 PPSA26344): PROBE-PRIMARY
     * (added in r19.57) caused save-triggered trophy regression. By querying
     * foreground user BEFORE pt_call into game, PHU's B6 fires register chain
     * earlier than game's natural register → daemon state race breaks the
     * save-triggered unlock chain.
     *
     * Option B fix: pt_call into game = PRIMARY (with retry loop to cover
     * game's libSceUserService init race window), PROBE-PRIMARY as FALLBACK
     * only if pt_call fails entirely (skip 4.03 probe lib not init). Restores
     * r17 timing while keeping multi-user safety net. */

    /* PRIMARY = pt_call into game (r17 method) with retry loop for race window */
    if (fn_get_fg_user > 0) {
        for (int retry = 0; retry < 6; retry++) { /* 6 × 500ms = 3s max */
            int32_t zero_uid = 0;
            pt_copyin(game_pid, &zero_uid, scratch_va + 4, 4);
            long rc_uid = pt_call(game_pid, fn_get_fg_user, (intptr_t)(scratch_va + 4));
            int32_t got_uid = 0;
            pt_copyout(game_pid, scratch_va + 4, &got_uid, 4);
            klog_printf("[trophy] B6 r19.67 PRIMARY pt_call GetForegroundUser retry=%d rc=0x%lx uid=%d\n",
                        retry, (uintptr_t)rc_uid, got_uid);
            if (got_uid > 1) {
                user_id = got_uid;
                phu_diag_log("trophy B6 fg_user pt_call OK retry=%d uid=%d", retry, got_uid);
                break;
            }
            if (retry < 5) usleep(500000);
        }
    }

    /* FALLBACK = PROBE-PRIMARY (only when pt_call failed entirely)
     * Skip on 4.03 (probe lib not init in raw payload context). */
    if (user_id <= 1 && (!e || !e->fw_label || strcmp(e->fw_label, "4.03") != 0)) {
        int init_rc = sceUserServiceInitialize2;
        klog_printf("[trophy] B6 r19.67 FALLBACK sceUserServiceInitialize2 rc=0x%x\n",
                    (unsigned)init_rc);

        int32_t probe_fg_uid = 0;
        int probe_rc = sceUserServiceGetForegroundUser((int *)&probe_fg_uid);
        klog_printf("[trophy] B6 r19.67 FALLBACK probe GetForegroundUser rc=0x%x uid=%d\n",
                    (unsigned)probe_rc, probe_fg_uid);
        phu_diag_log("trophy B6 fg_user probe-fallback rc=0x%x uid=%d",
                     (unsigned)probe_rc, probe_fg_uid);
        if (probe_fg_uid > 1) {
            user_id = probe_fg_uid;
        }
    }

    /* r19.13 PRIMARY (now secondary): sceNpUserGetUserIdList from NP layer.
     * Memory RE: "No PSN login required for local install — sceNpUserGetUserIdList suffit".
     * Daemon FUN_01d20340 CommitTrophyToUser calls this. Returns NP-aware user
     * IDs recognized by daemon's User::GetUser WITHOUT PSN sign-in. Works
     * for offact-activated accounts. */
    if (user_id <= 1 && fn_np_get_user_list > 0) {
        int32_t zero_users[20] = {0};
        int32_t zero_count = 0;
        pt_copyin(game_pid, zero_users, scratch_va + 4, sizeof(zero_users));
        pt_copyin(game_pid, &zero_count, scratch_va + 4 + sizeof(zero_users), 4);
        long rc_np = pt_call(game_pid, fn_np_get_user_list,
                             (intptr_t)(scratch_va + 4),
                             20,
                             (intptr_t)(scratch_va + 4 + sizeof(zero_users)));
        int32_t got_users[20] = {0};
        int32_t got_count = 0;
        pt_copyout(game_pid, scratch_va + 4, got_users, sizeof(got_users));
        pt_copyout(game_pid, scratch_va + 4 + sizeof(got_users), &got_count, 4);
        klog_printf("[trophy] B6 sceNpUserGetUserIdList rc=0x%lx count=%d users=[%d,%d,%d,%d]\n",
                    (uintptr_t)rc_np, got_count,
                    got_users[0], got_users[1], got_users[2], got_users[3]);
        phu_diag_log("trophy B6 np_user_list rc=0x%lx count=%d u0=%d",
                     (uintptr_t)rc_np, got_count, got_users[0]);
        if (got_count > 0 && got_users[0] > 0) {
            user_id = got_users[0];
            klog_printf("[trophy] B6 r19.13 PRIMARY hit — using NP user_id=%d\n", user_id);
        }
    }

    /* r19.57 fallback chain (only fires if all PRIMARY paths above didn't find
     * a valid foreground user): GetInitialUser → GetLoginUserIdList[0]. */
    if (user_id <= 1 && fn_get_initial_user > 0) {
        int32_t zero_uid = 0;
        pt_copyin(game_pid, &zero_uid, scratch_va + 4, 4);
        long rc_uid = pt_call(game_pid, fn_get_initial_user, (intptr_t)(scratch_va + 4));
        int32_t got_uid = 0;
        pt_copyout(game_pid, scratch_va + 4, &got_uid, 4);
        klog_printf("[trophy] B6 GetInitialUser rc=0x%lx got_uid=%d\n",
                    (uintptr_t)rc_uid, got_uid);
        phu_diag_log("trophy B6 initial_user rc=0x%lx uid=%d", (uintptr_t)rc_uid, got_uid);
        if (got_uid > 1) {
            user_id = got_uid;
        }
    }

    if (user_id <= 1 && fn_get_user_list > 0) {
        int32_t zero_list[16] = {0};
        pt_copyin(game_pid, zero_list, scratch_va + 4, sizeof(zero_list));
        long rc_uid = pt_call(game_pid, fn_get_user_list, (intptr_t)(scratch_va + 4));
        int32_t got_list[16] = {0};
        pt_copyout(game_pid, scratch_va + 4, got_list, sizeof(got_list));
        klog_printf("[trophy] B6 GetLoginUserIdList rc=0x%lx users=[%d,%d,%d,%d]\n",
                    (uintptr_t)rc_uid, got_list[0], got_list[1], got_list[2], got_list[3]);
        phu_diag_log("trophy B6 user_list rc=0x%lx u0=%d", (uintptr_t)rc_uid, got_list[0]);
        if (got_list[0] > 1) {
            user_id = got_list[0];
        }
    }

    /* r19.57 LAST-RESORT — /user/home/ FS scan. Was r19.17 PRIMARY (caused
     * regression: on consoles with multiple users / orphan dirs, picked
     * stale uid before foreground was queried). Demoted to LAST fallback —
     * fires only if every SceUserService + sceNpUserGetUserIdList path failed
     * (= rare orphan-install case). Picks the LOWEST numeric uid > 1 (= the
     * primary user typically).
     *
     * Pick lowest, not first, because readdir doesn't guarantee order. */
    if (user_id <= 1) {
        DIR *home = opendir("/user/home");
        if (home) {
            int32_t lowest_uid = 0;
            struct dirent *de;
            while ((de = readdir(home)) != NULL) {
                if (de->d_name[0] >= '0' && de->d_name[0] <= '9') {
                    long uid_candidate = atol(de->d_name);
                    if (uid_candidate > 1 &&
                        (lowest_uid == 0 || uid_candidate < lowest_uid)) {
                        lowest_uid = (int32_t)uid_candidate;
                    }
                }
            }
            closedir(home);
            if (lowest_uid > 1) {
                user_id = lowest_uid;
                klog_printf("[trophy] B6 r19.57 LAST-RESORT: found user_id=%d in /user/home/ "
                            "(all SceUserService + NpUserGetUserIdList paths failed)\n",
                            user_id);
                phu_diag_log("trophy B6 fs_scan LAST-RESORT: uid=%d", user_id);
            }
        }
    }

    klog_printf("[trophy] B6 using user_id=%d for CreateContext\n", user_id);

    /* 6. pt_call sceNpTrophy2CreateContext(&out_ctxId, user_id, options=0, reserved=0).
     * RE confirmed signature: (int *out, int user_id, uint options, long reserved).
     * arg2 = user_id (NOT commId — fixed in r14). Daemon: User::GetUser(user_id)
     * must succeed else 0x80553917. options must be < 100 else 0x8055391A.
     *
     * r15 — handles ALREADY_EXISTS via game-context-reuse path:
     * SceShellCore accepts the cmd 0x90000 IPC and returns a valid daemon
     * ctx_id, BUT libSceNpTrophy2's client-side cache (DAT_01018080+0x150)
     * rejects with 0x80553910 (CONTEXT_ALREADY_EXISTS) because the game
     * already has a context for this NpCommId. Solution: walk the client
     * table, find game's active ctx_id, reuse it. ctx_is_ours flag controls
     * cleanup so don't tear down the game's own state. */
    {
        long rc = pt_call(game_pid, fn_create_ctx,
                          (intptr_t)(scratch_va + 16), /* &out_ctxId → rdi */
                          (intptr_t)user_id, /* user_id → rsi */
                          (intptr_t)0, /* options=0 → rdx */
                          (intptr_t)0); /* reserved=0 → rcx */
        int32_t ctx_id = 0;
        pt_copyout(game_pid, scratch_va + 16, &ctx_id, 4);
        klog_printf("[trophy] B6 CreateContext rc=0x%lx ctxId=%d\n", (uintptr_t)rc, ctx_id);
        phu_diag_log("trophy B6 CreateContext rc=0x%lx ctxId=%d", (uintptr_t)rc, ctx_id);

        bool ctx_is_ours = true;

        if ((uint32_t)(rc & 0xFFFFFFFF) == 0x80553910 && ctx_id <= 0) {
            /* r15 reuse path: walk libSceNpTrophy2 client cache DAT_01018080
             * to find the game's active context. Compute runtime VA from the
             * resolved sceNpTrophy2CreateContext (offset 0x150 from RE). Read
             * the state pointer at DAT_01018080 (offset 0x18080 in image), then
             * iterate slots 0x158..0x350 looking for an active node (+0x14 != 0).
             * Each node has ctx_id at +0x08 (int32). Take the first active. */
            /* r19.4 — per-fw libSceNpTrophy2 offsets (identical 9.40+7.61 per
             * RE 2026-05-13, but lookup keeps r19.x infra ready for future fws). */
            uintptr_t lib_base = (uintptr_t)fn_create_ctx - e->tr2_create_ctx_offset;
            uintptr_t dat_state_va = lib_base + e->tr2_dat_state_offset;

            int64_t table_ptr = 0;
            pt_copyout(game_pid, (intptr_t)dat_state_va, &table_ptr, 8);
            klog_printf("[trophy] B6 r15 reuse: lib_base=0x%lx DAT_01018080@0x%lx "
                        "→ table_ptr=0x%lx\n",
                        lib_base, dat_state_va, (uintptr_t)table_ptr);

            if (table_ptr == 0) {
                klog_printf("[trophy] B6 r15 table_ptr NULL — abort\n");
                phu_diag_log("trophy B6 r15 table NULL");
                goto cleanup_mmap;
            }

            int32_t found_ctx = -1;
            for (intptr_t off = 0x158; off < 0x350; off += 8) {
                int64_t node_ptr = 0;
                pt_copyout(game_pid, (intptr_t)((uintptr_t)table_ptr + off),
                           &node_ptr, 8);
                if (node_ptr == 0) continue;

                uint8_t active = 0;
                pt_copyout(game_pid, (intptr_t)((uintptr_t)node_ptr + 0x14),
                           &active, 1);
                if (active == 0) continue;

                int32_t got_id = 0;
                pt_copyout(game_pid, (intptr_t)((uintptr_t)node_ptr + 0x08),
                           &got_id, 4);
                klog_printf("[trophy] B6 r15 active slot @ +0x%lx node=0x%lx "
                            "ctx_id=%d\n",
                            (uintptr_t)off, (uintptr_t)node_ptr, got_id);
                if (got_id > 0) {
                    found_ctx = got_id;
                    break;
                }
            }

            if (found_ctx <= 0) {
                klog_printf("[trophy] B6 r15 walk found no active ctx — abort\n");
                phu_diag_log("trophy B6 r15 no active ctx found");
                goto cleanup_mmap;
            }

            ctx_id = found_ctx;
            ctx_is_ours = false;
            klog_printf("[trophy] B6 r15 REUSING game's ctx_id=%d "
                        "(skip DestroyContext at cleanup)\n", ctx_id);
            phu_diag_log("trophy B6 r15 reuse ctx_id=%d", ctx_id);
        } else if ((int32_t)rc < 0 || ctx_id <= 0) {
            goto cleanup_mmap;
        }

        /* 7. pt_call sceNpTrophy2CreateHandle(&out_handleId).
         * Handles are process-local, can have multiple. Always the own. */
        long rc2 = pt_call(game_pid, fn_create_handle,
                           (intptr_t)(scratch_va + 20));
        int32_t handle_id = 0;
        pt_copyout(game_pid, scratch_va + 20, &handle_id, 4);
        klog_printf("[trophy] B6 CreateHandle rc=0x%lx handleId=%d\n", (uintptr_t)rc2, handle_id);
        phu_diag_log("trophy B6 CreateHandle rc=0x%lx handleId=%d", (uintptr_t)rc2, handle_id);
        if ((int32_t)rc2 < 0 || handle_id <= 0) {
            if (ctx_is_ours && fn_destroy_ctx > 0)
                pt_call(game_pid, fn_destroy_ctx, (intptr_t)ctx_id);
            goto cleanup_mmap;
        }

        /* 8. THE CRITICAL CALL — RegisterContext triggers daemon IPMI cmd 0x90016
         * which invokes the full B1+B2+B3+B4 patched chain to actually install
         * trophy files in /user/trophy/conf/NPWR*_00/.
         * Per RE: sceNpTrophy2RegisterContext(int ctxId, int handleId,
         * long reserved). arg3 MUST be 0 else returns 0x80553904 (not options).
         *
         * r15: if ctx_is_ours==false, game already registered → rc=0 or
         * rc=0x8094000F ALREADY_INSTALLED. Both mean trophies are in place. */
        long rc3 = pt_call(game_pid, fn_register_ctx,
                           (intptr_t)ctx_id,
                           (intptr_t)handle_id,
                           (intptr_t)0 /* reserved=0 (RE'd, not options) */);
        klog_printf("[trophy] B6 RegisterContext rc=0x%lx (ctx=%d %s, handle=%d) "
                    "(= daemon install result)\n",
                    (uintptr_t)rc3, ctx_id, ctx_is_ours ? "ours": "game's", handle_id);
        phu_diag_log("trophy B6 RegisterContext rc=0x%lx ctx=%d ours=%d",
                     (uintptr_t)rc3, ctx_id, (int)ctx_is_ours);

        /* rc3 == 0 -> /user/trophy(2)/conf/NPWR_00/TROPHY.UCP created.
         * rc3 == 0x80553921 → Trophy 2 non-fatal warning (= install completes
         * despite this code being returned). Empirically
         * verified r16 runtime 2026-05-13: trophies appeared
         * in PSN profile + /user/trophy2/nobackup/conf/NPWR
         * dir created. Treat as SUCCESS.
         * rc3 == 0x8094000F → SCE_LNC_UTIL_ERROR_NOT_SYSTEM_PROCESS (LncManager
         * attr gate). If seeing this with B5_LNC active,
         * the patch didn't take effect — log specifically.
         * rc3 negative other → see Sony error codes table in notes. */
        uint32_t rc3_u = (uint32_t)(rc3 & 0xFFFFFFFF);
        bool install_ok = ((int32_t)rc3 >= 0) || (rc3_u == 0x80553921);
        if (rc3_u == 0x8094000F) {
            klog_printf("[trophy] B6 ERROR: RegisterContext rc=0x8094000F "
                        "= LncManager attr gate. B5_LNC patch may not have applied\n");
        }
        if (rc3_u == 0x80553921) {
            klog_printf("[trophy] B6 INFO: RegisterContext rc=0x80553921 "
                        "= Trophy 2 non-fatal warning (install completes; "
                        "verified PSN profile display)\n");
        }
        final_rc = install_ok ? 0: -1;

        /* ============================================================================
         * r19.9 — DEBUG UNLOCK LOOP (10.01 + future fws where RegisterContext path A+B dead)
         * ----------------------------------------------------------------------------
         * Defense-in-depth: after RegisterContext attempt (success OR fail), if B5
         * patch is active for this fw, ALSO call sceNpTrophy2SystemDebugUnlockTrophy
         * for each potential trophy_id 0..127. Each call sends IPMI 0x90018 to daemon
         * → DebugUnlockTrophyIpcJob enqueued → worker unlocks trophy directly.
         *
         * unlock_spec layout: int{2} = { type=1 (by trophy_id), trophy_id }
         * Writes spec to game scratch buffer, pt_call SystemDebugUnlockTrophy.
         * Invalid trophy_ids return error 0x80553904 = ignored, only valid succeed.
         * ============================================================================ */
        const phu_trophy_fw_offsets_t *e_dbg = get_fw_offsets;
        if (e_dbg && e_dbg->b5_auth_bypass_va != 0 && fn_debug_unlock > 0
            && ctx_id > 0 && handle_id > 0) {
            klog_printf("[trophy] r19.9 DebugUnlock loop START (ctx=%d handle=%d "
                        "fn_debug_unlock=0x%lx)\n",
                        ctx_id, handle_id, (uintptr_t)fn_debug_unlock);
            phu_diag_log("trophy r19.9 DebugUnlock loop start ctx=%d handle=%d",
                         ctx_id, handle_id);

            /* Use scratch buffer at offset +256 for unlock_spec (8 bytes). */
            intptr_t spec_va = scratch_va + 256;
            int unlock_ok = 0, unlock_fail = 0;
            for (int trophy_id = 0; trophy_id < 128; trophy_id++) {
                uint32_t spec[2] = { 1, (uint32_t)trophy_id }; /* type=1, trophy_id */
                pt_copyin(game_pid, &spec, spec_va, sizeof(spec));
                long rc_unlock = pt_call(game_pid, fn_debug_unlock,
                                         (intptr_t)ctx_id,
                                         (intptr_t)handle_id,
                                         spec_va);
                if ((int32_t)rc_unlock >= 0) {
                    unlock_ok++;
                } else {
                    unlock_fail++;
                }
                /* Log only first 3 + last results to avoid klog spam */
                if (trophy_id < 3) {
                    klog_printf("[trophy] r19.9 unlock trophy_id=%d rc=0x%lx\n",
                                trophy_id, (uintptr_t)rc_unlock);
                }
            }
            klog_printf("[trophy] r19.9 DebugUnlock loop DONE: %d ok / %d fail out of 128 tries\n",
                        unlock_ok, unlock_fail);
            phu_diag_log("trophy r19.9 DebugUnlock: %d ok / %d fail", unlock_ok, unlock_fail);

            /* If RegisterContext failed but DebugUnlock had ANY success, treat as success.
             * Trophies that got unlocked appear in profile = user-visible success. */
            if (unlock_ok > 0 && final_rc != 0) {
                klog_printf("[trophy] r19.9 RegisterContext failed BUT %d trophies unlocked "
                            "via DebugUnlock — treating as success\n", unlock_ok);
                final_rc = 0;
            }
        } else if (e_dbg && e_dbg->b5_auth_bypass_va != 0) {
            klog_printf("[trophy] r19.9 DebugUnlock SKIP: prereq missing "
                        "(fn=0x%lx ctx=%d handle=%d)\n",
                        (uintptr_t)fn_debug_unlock, ctx_id, handle_id);
        }
        /* else: fw doesn't need DebugUnlock (9.40/7.61 work via RegisterContext) */

        /* 9. Cleanup: destroy handle (always PHU-owned). Destroy ctx ONLY if PHU
         * created it — never tear down the game's own context. */
        if (fn_destroy_handle > 0)
            pt_call(game_pid, fn_destroy_handle, (intptr_t)handle_id);
        if (ctx_is_ours && fn_destroy_ctx > 0)
            pt_call(game_pid, fn_destroy_ctx, (intptr_t)ctx_id);
    }

cleanup_mmap:
    pt_munmap(game_pid, scratch_va, 4096);

detach:
    /* Non-etaHEN PT_DETACH pattern (PT_CLEAN_DETACH macro from hook_vout.cpp):
     * pt_detach with SIGCONT, then follow-up kill(SIGCONT) to flush libNineS
     * internal PT state. Without the second signal, cycle-2 calls into the same
     * game (e.g. another B6 run, cheat toggle) hit double-attach mDBG hang. */
    pt_detach(game_pid, SIGCONT);
    kill(game_pid, SIGCONT);

    if (final_rc == 0) {
        klog_printf("[trophy] B6 SUCCESS — trophies installed for %s (user=%d)\n",
                    titleid, user_id);
        phu_notify("PHU Trophy: install OK — check profile");
        /* Mark this titleid as done so subsequent apply_per_game cycles skip B6. */
        strncpy(g_b6_done_titleid, titleid, sizeof(g_b6_done_titleid) - 1);
        g_b6_done_titleid[sizeof(g_b6_done_titleid) - 1] = '\0';
    } else {
        klog_printf("[trophy] B6 FAILED rc=%d — trophies NOT installed for %s\n",
                    final_rc, titleid);
    }
    return final_rc;
}

extern "C" int phu_trophy_check_persistence(void) {
    if (!g_phu_cfg.trophy_unlock_enabled) return 1;
    if (!g_phu_cfg.trophy_unlock_persistence_check) return 1;
    if (!g_phu_cfg.trophy_unlock_daemon_patch) return 1;
    if (!fw_is_supported) return 1;

    /* r19.32 — gate on lazy init. If patches were never applied this session,
     * SceShellCore is supposed to be vanilla — don't aggressively re-patch
     * just because see AAAA_ORIGINAL bytes. This was the bug: persistence
     * check would re-apply patches every game cycle (even for PS4 BC games),
     * breaking the next PS4 BC launch via Sony's trophy promote cascade. */
    if (!g_trophy_lazy_init_done) {
        return 1; /* No patches to maintain — vanilla state is intentional */
    }

    /* Resolve SceShellCore via title_id (NPXS40082). See init_boot for why
     * use title_id instead of name-match. */
    struct proc *sc_proc = get_proc_by_title_id("NPXS40082");
    if (!sc_proc) return 1;
    int shellcore_pid = phu_proc_get_pid(sc_proc);
    free(sc_proc);
    if (shellcore_pid <= 0) return 1;

    UniquePtr<Hijacker> hj = Hijacker::getHijacker(shellcore_pid);
    if (!hj) return 1;
    uintptr_t shellcore_base = hj->imagebase;
    if (shellcore_base == 0) return 1;

    bool resumed = phu_kstuff_ctrl_temporary_resume_for_op;

    uintptr_t image_base = probe_image_base((pid_t)shellcore_pid, shellcore_base);
    if (image_base == (uintptr_t)-1) {
        phu_kstuff_ctrl_restore_after_op(resumed);
        return 1; /* probe failed, don't blindly re-patch */
    }

    /* Read back the first string slot — if it's still "ZZZZZZZZZ", patch persists.
     * r19.4 — per-fw lookup. fw_is_supported gate upstream guarantees e != NULL. */
    const phu_trophy_fw_offsets_t *e = get_fw_offsets;
    if (!e) {
        phu_kstuff_ctrl_restore_after_op(resumed);
        return 1;
    }
    char buf[10] = {0};
    uintptr_t va = shellcore_base + (e->aaaa_slots[0] - image_base);
    if (!prw::proc_read((pid_t)shellcore_pid, va, buf, 9)) {
        phu_kstuff_ctrl_restore_after_op(resumed);
        return 1; /* read failed — keep last-known state, don't spam re-apply */
    }
    if (memcmp(buf, AAAA_PATCHED, 9) == 0) {
        phu_kstuff_ctrl_restore_after_op(resumed);
        return 1; /* still patched, all good */
    }
    if (memcmp(buf, AAAA_ORIGINAL, 9) == 0) {
        /* SceShellCore was restarted by Sony — ALL patches gone.
         * r19.57 audit C3 — Re-apply the COMPLETE chain, not just B1+B3+B4+B5_LNC.
         * Pre-fix, B5_auth (10.01), B13/B14/B15 (8.00/10.01), B16 (10.01),
         * B17 (10.01) and B20+B21+B22 (4.03/6.02) were left missing → trophy
         * install for the next game silently failed because the apply_per_game
         * gate only checks g_b1/3/4/5_lnc_full_done. The missing patches'
         * flags were never cleared, so the gate passed despite SceShellCore
         * being in a half-patched state. */
        klog_printf("[trophy] persistence: SceShellCore reverted to 'AAAA00000' "
                    "(restart ?) — re-applying full patch chain\n");
        phu_diag_log("trophy persistence: re-applying full chain after SceShellCore restart");
        int re_b1 = do_daemon_patch((pid_t)shellcore_pid, shellcore_base,
                                    image_base, /*verify_pre*/ true);
        int re_b3 = do_crypto_bypass_patch((pid_t)shellcore_pid, shellcore_base,
                                           image_base);
        int re_b4 = do_app_inventory_bypass_patch((pid_t)shellcore_pid, shellcore_base,
                                                  image_base);
        int re_b5_lnc = -1;
        if (g_phu_cfg.trophy_lnc_attr_bypass_enabled) {
            re_b5_lnc = do_lnc_attr_bypass_patch((pid_t)shellcore_pid, shellcore_base,
                                                  image_base);
        }

        /* r19.57 C3 — Critical for 10.01: B5 auth + B13/B14/B15 + B16 + B17
         * + B18. Each function self-gates via == 0 / fw_label check, so
         * calling on non-10.01 firmwares is a no-op (returns 1 "not-needed"). */
        int re_b5_auth = do_b5_auth_bypass_patch((pid_t)shellcore_pid,
                                                  shellcore_base, image_base);
        int re_b13 = do_b13_user_getuser_patch((pid_t)shellcore_pid);
        int re_b14 = do_b14_isloggedin_patch((pid_t)shellcore_pid);
        int re_b15 = do_b15_isguest_patch((pid_t)shellcore_pid);
        int re_b16 = do_b16_user_status_patch((pid_t)shellcore_pid,
                                               shellcore_base, image_base);
        int re_b17 = do_b17_register_391e_patch((pid_t)shellcore_pid,
                                                 shellcore_base, image_base);
        int re_b18 = do_b18_force_firsttime_path((pid_t)shellcore_pid,
                                                  shellcore_base, image_base);

        /* r19.57 C3 — Critical for 4.03 / 6.02 trophy display fix. Gated by
         * cfg.trophy_summary_bypass_enabled (mirror init_boot logic). */
        int re_b20 = -1, re_b21 = -1, re_b22 = -1;
        if (g_phu_cfg.trophy_summary_bypass_enabled) {
            re_b20 = do_b20_isdeprecated_bypass_patch((pid_t)shellcore_pid,
                                                       shellcore_base, image_base);
            re_b21 = do_b21_recovery_setter_disable_patch((pid_t)shellcore_pid,
                                                           shellcore_base, image_base);
            re_b22 = do_b22_recovery_read_bypass_patch((pid_t)shellcore_pid,
                                                        shellcore_base, image_base);
        } else if (g_phu_cfg.trophy_isdeprecated_bypass) {
            /* r19.67 B20-only safe re-apply (mirrors init_boot logic). */
            re_b20 = do_b20_isdeprecated_bypass_patch((pid_t)shellcore_pid,
                                                       shellcore_base, image_base);
        }

        phu_kstuff_ctrl_restore_after_op(resumed);
        klog_printf("[trophy] persistence: re-patched B1=%d/4 B3=%d/2 B4=%d/1 B5_LNC=%d/1 "
                    "B5auth=%d B13=%d B14=%d B15=%d B16=%d B17=%d B18=%d "
                    "B20=%d B21=%d B22=%d\n",
                    re_b1, re_b3, re_b4, re_b5_lnc,
                    re_b5_auth, re_b13, re_b14, re_b15, re_b16, re_b17, re_b18,
                    re_b20, re_b21, re_b22);
        phu_diag_log("trophy persistence: re-patched B1=%d B3=%d B4=%d B5_LNC=%d "
                     "B5auth=%d B13=%d B14=%d B15=%d B16=%d B17=%d B18=%d "
                     "B20=%d B21=%d B22=%d",
                     re_b1, re_b3, re_b4, re_b5_lnc,
                     re_b5_auth, re_b13, re_b14, re_b15, re_b16, re_b17, re_b18,
                     re_b20, re_b21, re_b22);

        /* Update done flags — apply_per_game gates on these. */
        g_b1_full_done = (re_b1 == 4);
        g_b3_full_done = (re_b3 == 2);
        g_b4_full_done = (re_b4 == 1);
        g_b5_lnc_full_done = (re_b5_lnc == 1
                              || !g_phu_cfg.trophy_lnc_attr_bypass_enabled);
        /* SceShellCore restart = new trophy install opportunity. Reset session
         * gate so games get B6 re-trigger if user relaunches them. */
        g_b6_done_titleid[0] = '\0';
        return 0;
    }
    /* Unknown content — log but don't act (safer than panic-rewrite). */
    klog_printf("[trophy] persistence: slot 0 unexpected '%.9s' — leave alone\n", buf);
    phu_kstuff_ctrl_restore_after_op(resumed);
    return 1;
}

extern "C" void phu_trophy_show_warn_notif(void) {
    phu_notify("PHU Trophy unlock ON — local only. DO NOT sync PSN on main account.");
    klog_printf("[trophy] warn notif shown to user\n");
}
