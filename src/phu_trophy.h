#pragma once
/*
 * phu_trophy.h — v1.15.0 trophy unlock orchestrator (Phase A skeleton).
 *
 * Architecture (final, post-RE 2026-05-12) :
 *
 *   ┌─────────────────────────────────────────────────────────────┐
 *   │  Game process                                                │
 *   │  ├─ sceNpTrophyRegisterContext (libSceNpTrophy)              │
 *   │  └─ sceNpIntGetNpTitleIdSecret (libSceNpManager)             │
 *   │     └─ reads from DAT_01063128 + 0x14 (titleid 16B)          │
 *   │                                 + 0x24 (secret 128B)        │
 *   │     ↑ INJECT POINT 1 : ptrace pt_copyin                     │
 *   └─────────────────────────────────────────────────────────────┘
 *                          │ IPMI cmd 'GREG' / 'GUNL'
 *                          ▼
 *   ┌─────────────────────────────────────────────────────────────┐
 *   │  SceShellCore.elf — SceNpTrophy daemon process              │
 *   │  ├─ TrophyConf::IsFakeNpCommId() ← THE GATE                 │
 *   │  └─ compares commid to hardcoded "AAAA00000" string         │
 *   │     at 4 addresses : 0x02e7f488, f494, fbe8, fbf4           │
 *   │     ↑ INJECT POINT 2 : DMAP write (no UI freeze)            │
 *   └─────────────────────────────────────────────────────────────┘
 *
 * 2 inject points = 2 methods :
 *   1. PTRACE on game process for client-side cache (no kstuff dep)
 *   2. DMAP on SceShellCore for daemon-side string patch (no UI freeze)
 *
 * Phase A (THIS FILE) :
 *   - Cfg-gated stubs
 *   - Klog tracing of would-be operations
 *   - No actual memory writes yet (B1 + B2 do that)
 *
 * Phase B1 v1.15.0-β1 :
 *   - phu_trophy_init_boot() implements SceShellCore DMAP string patch
 *
 * Phase B2 v1.15.0-β2 :
 *   - phu_trophy_apply_per_game() implements ptrace cache inject
 *
 * Phase B3 v1.15.0-β3 :
 *   - phu_trophy_check_persistence() implements SceShellCore restart detection
 *
 * ⚠️ Safety : every entry point checks cfg.trophy_unlock_enabled FIRST.
 *    Master switch OFF = whole subsystem is a no-op. PSN ban risk = paranoid
 *    defaults. User must explicit opt-in via cfg.
 */

#ifdef __cplusplus
extern "C" {
#endif

/* Called once at PHU boot, after kstuff init.
 *
 * If cfg.trophy_unlock_enabled && cfg.trophy_unlock_daemon_patch :
 *   1. kstuff_temporary_resume_for_op
 *   2. DMAP patch SceShellCore "AAAA00000" → "ZZZZZZZZZ" (4 occurrences)
 *   3. kstuff_restore_after_op
 *   4. klog "[trophy] daemon-side gate patched"
 *
 * Returns 0 on success, -1 on failure (logged via klog).
 * Phase A stub : returns 0 + klog "[trophy] STUB skeleton — would patch here".
 */
int phu_trophy_init_boot(void);

/* Called from probe each time a game is detected (game_pid + titleid known).
 *
 * If cfg.trophy_unlock_enabled && cfg.trophy_unlock_client_inject :
 *   1. Check whitelist cfg.trophy_unlock_titleids (empty = all)
 *   2. pt_attach(game_pid)
 *   3. Resolve libSceNpManager base in game proc
 *   4. pt_copyin fake_titleid (16B) + fake_secret (128B != 0) into ctx
 *   5. Set flag bytes +0xa4, +0xa5, +0xa6 = 1
 *   6. pt_detach(game_pid, SIGCONT)
 *   7. klog "[trophy] client-side cache injected for <TID>"
 *
 * Returns 0 on success / skipped (cfg OFF / not whitelisted), -1 on failure.
 * Phase A stub : returns 0 + klog if cfg enabled.
 */
int phu_trophy_apply_per_game(int game_pid, const char *titleid);

/* Phase B6 — force-install trophies for dumps that don't call
 * sceNpTrophy2RegisterContext on their own (Astro Bot dump etc.).
 *
 * Strategy : pt_attach into game_pid, resolve sceNpTrophy2* exports via
 * kernel_dynlib_handle/dlsym, pt_mmap a 16-byte output buffer in game AS,
 * then pt_call the install sequence :
 *   CreateContext -> CreateHandle -> RegisterContext (= TRIGGERS daemon
 *   install via IPMI cmd 0x90016).
 * Cleanup : DestroyHandle / DestroyContext / pt_munmap / pt_detach(SIGCONT).
 *
 * Pre-conditions : B1 + B2 already applied (apply_per_game just above).
 *
 * Returns 0 on install triggered, -1 on resolve/pt failure, +1 if skipped
 * (cfg OFF, libSceNpTrophy2 not loaded, npbind.dat missing — game probably
 * already has trophies on this title or it's a non-trophy game).
 */
int phu_trophy_force_install_via_ptcall(int game_pid, const char *titleid);

/* Called periodically (e.g. each game-detect cycle) to verify the SceShellCore
 * string patch is still in place. If SceShellCore crashed and Sony respawned
 * it, the patch is lost — re-apply.
 *
 * Returns 1 if patch is OK, 0 if re-patched, -1 on failure.
 * Phase A stub : returns 1.
 */
int phu_trophy_check_persistence(void);

/* r19.32 — Restore SceShellCore to vanilla state. Called by probe at game-
 * vanish so subsequent game launch (PS4 BC fpkg OR PS5 native dump) sees a
 * clean SceShellCore — fixing Sony's sceNpTrophyVshPromoteCheckRecoveryRequired2
 * 0x80551618 cascade that breaks PS4 BC launch when patches are active.
 *
 * Idempotent : safe to call even when no patches were applied (no-op).
 * Returns 0 on success / no-op, -1 on partial fail (some sites not restored).
 *
 * Architecture : pairs with the lazy init_boot in phu_trophy_apply_per_game.
 *   First PS5 native game-detect → lazy init applies patches + records pre-bytes
 *   Game vanishes               → rollback restores pre-bytes, clears registry
 *   Next PS4 BC game            → vanilla SceShellCore → Sony chain intact
 *   Next PS5 native game        → lazy init fires again (clean state) */
int phu_trophy_rollback_boot(void);

/* Show explicit Sony notif warning the user that trophy unlock is active and
 * that PSN sync will be blocked / risky. Called from init_boot if
 * cfg.trophy_unlock_warn_notif is set.
 *
 * Notif text : "PHU Trophy unlock ON — local only. DO NOT sync PSN on main account."
 */
void phu_trophy_show_warn_notif(void);

/* r19.39 — Trophy nuclear reset via cfg key.
 *
 * Triggered by cfg.trophy_reset_pending == 1 (read from /user/data/PHU/phu_overlay.cfg).
 * Wipes the 3 trophy state paths (anti-cascade : truncate + delete + 50ms sleep) :
 *   - /user/home/<uid_hex>/trophy/       (per user)
 *   - /user/trophy/conf/                 (Trophy v1 PS4 NPWR configs)
 *   - /user/trophy2/nobackup/conf/       (Trophy v2 PS5 NPWR configs)
 *
 * Preserved (NEVER touched) : /user/system/share/trophy/predata + material
 * (= Sony seed required for daemon first-boot init from clean slate).
 *
 * Loop prevention : creates sentinel /user/data/PHU/trophy_reset_done after wipe.
 * If sentinel exists at boot + cfg=1 → skips re-wipe + logs warning. User must
 * edit cfg to 0 + delete sentinel manually to re-arm.
 *
 * Should be called EARLY in boot, before phu_trophy_init_boot, so SceShellCore
 * is not patched while files are being wiped.
 *
 * Returns : 0 if not triggered (cfg=0 OR sentinel exists), > 0 = files wiped.
 */
int phu_trophy_reset_check_and_execute(void);

#ifdef __cplusplus
}
#endif
