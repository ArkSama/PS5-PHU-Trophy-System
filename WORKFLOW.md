# Workflow — how it works

For devs who want to integrate trophy install into their own PS5 payload.
This doc covers how Sony's trophy system works internally, and where the
hooks/patches go to bypass the checks on dumped games.

No prereq beyond knowing how a jailbreak PS5 payload works
(libhijacker, ptrace, DMAP kernel reads).

---

## 1. Sony's pipeline

When a PS5 game calls `sceNpTrophy2RegisterContext`, the chain is :

```
GAME (process X)
  └─ libSceNpTrophy2.sprx :: sceNpTrophy2RegisterContext
       └─ IPMI cmd 0x90016 (via libSceIpmi)
            └─ SceShellCore (daemon, NPXS40082)
                 └─ FUN_01d7b310 (IPMI handler)
                      └─ ... chain of checks ...
                           └─ writes /user/trophy2/nobackup/conf/<NPWR>/TROPHY.UCP
```

SceShellCore is **the boss** — it decides whether the register goes through.
All patches target this binary (except B2 + B6 which are game-side, explained
below).

The daemon has multiple gates :
- **Gate 0** : NPWR exists check via NpAsmClient cache
- **Gate 1** : titleid in app inventory
- **Gate 2** : LncManager attr & 0x6 (system process check)
- **Gate 3** : crypto / file loader returns valid signature
- **Gate 4** : User::GetUser / IsLoggedIn / IsGuest (Cronos era)
- **Gate 5** : storage commit (TROPHY.UCP creation)

A **properly fpkg-installed** game passes all these gates because Sony
signed the artifacts. A **dump** fails because :
- no valid signature (commId hardcoded "AAAA00000" rejected)
- titleid not in app inventory
- npbind.dat in the wrong path

---

## 2. B-patches architecture

Each patch has a name (B1, B2, B3, etc.) corresponding to a bypassed Sony step. The numbering follows discovery order.

### Pre-Cronos (4.03 → 9.40)

Classic pipeline. 7 universal patches + 3 specials for 4.03/6.02.

```
B1   strings "AAAA00000" → "ZZZZZZZZZ" in SceShellCore (×4 sites)
B3   crypto stubs → xor eax,eax;ret (×2 funcs)
B4   app inventory wrapper → force category=2 + return 0
B5_LNC  LncManager attr JZ → 2 NOPs (short JZ) or 6 NOPs (long JZ)
B2   inject NpAsmClient cache (game-side libSceNpManager)
B7   copy npbind.dat + trophy00.ucp into /system_data/priv/appmeta/<TID>/
B6   pt_call sceNpTrophy2RegisterContext in the game (force-install)
B20  IsDeprecatedVersion → return FALSE  (4.03, 6.02 only)
B21  RecoveryRequired setter disabled    (4.03, 6.02 only)
B22  RecoveryRequired reader bypass      (4.03, 6.02 only)
```

### Cronos (10.00 → 12.70)

Sony refactored everything. The daemon now uses
`AppSubcontainerPrepareNpForCronos` which auto-prepares the files from
the dumped PKG. So B7 is useless. B3 patches a file-loader (not a crypto
stub) and patching it = sabotage → B3 disabled on Cronos.

Cronos has strict User checks → B13/B14/B15 active.

```
B1, B4, B5_LNC, B2, B6      ← active (universal)
B3                          ← DISABLED (file loader, not crypto stub)
B7                          ← skip (Sony auto-prepare)
B11                         ← BindLocal init (10.01 only)
B13, B14, B15, B16, B17     ← User state bypass (Cronos)
```

### Hybrid (8.00)

Cronos infrastructure compiled but inert (`sceKernelIsCronos` returns 0).
Behavior strict like Cronos on User checks → B13/14/15 active. B3 sabotage
like 10.01 → disabled.

---

## 3. Full flow

```c
// Probe boot — patches NOT applied yet (vanilla SceShellCore)
//   ↓
// Game launches (PPSA*) → probe detects via allproc scan
//   ↓
// phu_trophy_apply_per_game(game_pid, "PPSA12345")
//   ├─ check : titleid is PS5 native (PPSA* / PPSB*) ?
//   ├─ check : whitelist cfg if configured
//   ├─ check : trophy already installed ? (= TROPHY.UCP exists)
//   │
//   ├─ phu_trophy_init_boot()  [LAZY, fires on 1st PS5 game cycle]
//   │     ├─ resolve SceShellCore via NPXS40082
//   │     ├─ probe image_base (0x01000000 or 0x00000000)
//   │     ├─ kstuff pause (DMAP write window)
//   │     ├─ patch B1 ×4 strings
//   │     ├─ patch B3 ×2 funcs (or disabled-by-design depending on fw)
//   │     ├─ patch B4 (app inventory)
//   │     ├─ patch B5_LNC (NOP JZ)
//   │     ├─ patch B8-B18 conditional per fw
//   │     ├─ patch B20+B21+B22 if cfg trophy_summary_bypass_enabled
//   │     └─ kstuff resume
//   │
//   ├─ phu_trophy_setup_appmeta()  [B7]
//   │     ├─ mkdir /system_data/priv/appmeta/<TID>/trophy2/
//   │     ├─ copy /user/app/<TID>/sce_sys/trophy2/npbind.dat → above
//   │     └─ copy /user/app/<TID>/sce_sys/trophy2/trophy00.ucp → above
//   │
//   ├─ phu_trophy_inject_npasmclient()  [B2]
//   │     ├─ resolve libSceNpManager.sprx in the game via kernel_dynlib_handle
//   │     ├─ poll DAT_01063128 until NpAsmClient init (max 5s)
//   │     ├─ DMAP-write title=titleid+"_00" at +0x14
//   │     ├─ DMAP-write secret 128B (anything > 0) at +0x24
//   │     └─ DMAP-write flags +0xa4=1 +0xa5=1 +0xa6=1
//   │
//   └─ phu_trophy_force_install()  [B6]
//         ├─ pt_attach game_pid
//         ├─ resolve user_id (foreground user PRIMARY)
//         ├─ pt_call sceNpTrophy2CreateContext(user_id) → ctx_id
//         │     └─ if 0x80553910 ALREADY_EXISTS, walk DAT_01018080 table + reuse
//         ├─ pt_call sceNpTrophy2CreateHandle(ctx_id) → handle_id
//         ├─ pt_call sceNpTrophy2RegisterContext(ctx_id, handle_id, 0)
//         │     └─ daemon walks Sony chain : npbind decrypt → NPWR resolve →
//         │        TROPHY.UCP allocate → return rc (0 = pure success,
//         │        0x80553921 = warning install OK, 0x8055390c = fail)
//         └─ pt_detach SIGCONT + kill SIGCONT (libNineS pattern)
//
// Sampler loop runs (FPS overlay, cheat engine, etc.)
//   ↓
// Game vanishes (probe detects via 3-strikes scan miss)
//   ↓
// phu_trophy_rollback_boot()
//   ├─ resolve SceShellCore (skip if pid changed = respawn)
//   ├─ kstuff pause
//   ├─ DMAP-write originals from g_rollback_sites[] registry
//   ├─ kernel_mprotect flush (µop cache + TLB)
//   ├─ kstuff resume
//   └─ clear g_trophy_lazy_init_done flag
//
// SceShellCore is back to vanilla → next PS4 BC launch works OK
```

---

## 4. Why this architecture

### Why rollback at game vanish

If B1+B3+B4+B5_LNC stay active on SceShellCore permanently, the next
launch of a **PS4 BC fpkg game** (properly installed) hits
`sceNpTrophyVshPromoteCheckRecoveryRequired2` which sees the patched
strings and returns `0x80551618` → NPDRM deletes the license → game launch
abort → black screen, back to XMB.

Rollback at game vanish restores SceShellCore to vanilla → PS4 BC works on
the next launch. **Polyvalent** in the same session, no reboot needed.

### Why force-full-chain on every game cycle

Consequence of rollback : SceShellCore is vanilla between game launches.
So every new game cycle, patches must be re-applied or register fails.

Cost : ~500ms of idempotent DMAP writes per launch (out of ~30-60s game
boot). Negligible.

Bonus : **multi-user works automatically**. When user2 launches the same
game after user1, lazy_init fires again → patches re-active → game's
natural RegisterContext call (which uses foreground user automatically)
registers user2 successfully.

### Why B6 can fail (and that's fine)

B6 (force-install via pt_call) is a secondary path. If the game just
started and its libSceUserService isn't initialized yet, all pt_call
queries return `0x80960002 NOT_INITIALIZED` → fallback to `/user/home/`
scan → stale uid → CreateContext fails with `0x80553917 USER_NOT_FOUND`.

This is cosmetic. The **game itself** calls RegisterContext a few seconds
later (when it's ready) with its libSceUserService initialized. At that
point :
- foreground user = correct
- hits PATCHED SceShellCore (because patches were re-applied)
- daemon accepts the register

→ Trophy installed correctly even if B6 reports FAILED.

### Why B2 is game-side

NpAsmClient is a singleton in `libSceNpManager.sprx` loaded in **the
game's process**. The daemon (SceShellCore) has its own libSceNpManager
but it's the client-side that decides which commId to send in the IPMI
request.

If the game's NpAsmClient has a "AAAA00000" hardcoded commId (because
it's a dump), Sony's daemon rejects. B2 injects directly into the game's
libSceNpManager to set a credible commId/secret BEFORE the game makes
its register call.

### Why B7 in `/system_data/priv/appmeta/`

Sony's daemon reads `npbind.dat` from this canonical path (= where the
PKG installer places files). A dump has the files in
`/user/app/<TID>/sce_sys/trophy2/` but not in `/system_data/priv/appmeta/`.
B7 just copies them over.

On Cronos (10.x+), Sony's `AppSubcontainerPrepareNpForCronos` auto-prepares
these files from the PKG signature → B7 redundant on Cronos but harmless
(skip-if-exists).

---

## 5. Special case — B20+B21+B22 trio (early launch firmwares)

Sony has a design bug on early firmwares :

```c
// CreateUserDataFile initializes the version field to 0x10000
// IsDeprecatedVersion check (*file+0x68 == 0x10000) → always TRUE
// UpdateSummaryFile gate fires DELETE path → trpsummary.dat deleted
// Profile reads trpsummary → file missing → displays 0/0/0/0
```

The trio fix :
- **B20** : `IsDeprecatedVersion` → return FALSE (never deprecated)
- **B21** : `RecoveryRequired setter` → disabled (never sets flag)
- **B22** : `RecoveryRequired reader` → return 0 (even if flag set on-disk)

→ `UpdateSummaryFile` cascade takes the WRITE path → trpsummary.dat
regenerated → profile displays trophies correctly.

Per-fw status :
- **4.03** : trio ENABLED by default (= confirmed needed via beta tester
  feedback "trophies show in profile but unlock fail in-game").
- **4.50 / 4.51** : same Sony bug confirmed byte-exact, VAs RE'd, but
  trio DISABLED by default. Conservative — 4.03 baseline worked without
  it until beta testers reported the unlock-fail symptom. Flip
  `trophy_summary_bypass_enabled = 1` in cfg to enable.
- **6.02** : pre-Cronos hybrid inheriting the same bug, trio ENABLED by
  default (= mirror 4.03 logic, same symptom expected).
- **5.02, 5.50, 6.50, 7.x+** : Sony fixed it on these → trio = 0 (skip).

---

## 6. Multi-user

PS5 supports multiple users. Trophy storage is **per-NPWR + per-user** :
- `/user/trophy2/nobackup/conf/<NPWR>/TROPHY.UCP` — shared (per NPWR)
- `/user/home/<userid_hex>/trophy/...` — per-user state

When user2 launches a game that user1 installed, the daemon must register
user2 in the existing `TROPHY.UCP` storage. For this :

1. SceShellCore patches must be ACTIVE at register-call time
2. The foreground user query must return user2 (not stale user1)

**Force-full-chain** guarantees point 1.
**user_id fallback chain** guarantees point 2 :

```
1. sceUserServiceGetForegroundUser (PRIMARY)
2. sceNpUserGetUserIdList[0]
3. sceUserServiceGetInitialUser
4. sceUserServiceGetLoginUserIdList[0]
5. scan /user/home/<uid>/ (LAST RESORT, lowest uid > 1)
```

On 9.40 : the game's natural register call uses sceUserServiceGetForegroundUser
automatically → finds user2 → register OK.

On 10.01 Cronos : daemon-side User checks are strict → need B13/B14/B15
active (force return success regardless of user state).

---

## 7. Integration into your payload

### Required deps

- **libhijacker** : `kernel_copyout` / `kernel_copyin` (DMAP cross-process)
- **libNineS** : `get_proc_by_title_id` / `pt_attach` / `pt_call` / `pt_copyout`
- **ps5-payload-sdk** : `kernel_mprotect`, sceKernel symbols, etc.

### Public entry points

See `phu_trophy.h` :

```c
int phu_trophy_init_boot(void);             // applies SceShellCore patches
int phu_trophy_apply_per_game(int pid, const char *titleid);  // full chain
int phu_trophy_rollback_boot(void);         // restore vanilla
int phu_trophy_check_persistence(void);     // re-apply after respawn
int phu_trophy_reset_check_and_execute(void);  // state reset (4.03 trpsummary regen)
```

### Integration workflow

```c
// Payload boot :
//   1. detect fw via sysctl kern.sdk_version
//   2. lookup fw entry in g_trophy_fw_table[]
//   3. if (!supported) bail out (PS4 BC handles trophies via Sony native)

// Per game cycle in your main loop :
on_game_detected(pid, titleid) {
    phu_trophy_apply_per_game(pid, titleid);
    // ... your other stuff (FPS overlay, cheats, etc.) ...
}

on_game_vanished() {
    phu_trophy_rollback_boot();
}

// Optional : periodic re-verify daemon state
each_5_seconds() {
    phu_trophy_check_persistence();
}
```

### Useful cfg flags

```c
trophy_unlock_enabled            = 1  // master switch
trophy_unlock_daemon_patch       = 1  // B1+B3+B4+B5_LNC
trophy_unlock_client_inject      = 1  // B2 + B6
trophy_appmeta_setup_enabled     = 1  // B7
trophy_lnc_attr_bypass_enabled   = 1  // B5_LNC
trophy_summary_bypass_enabled    = 1  // B20+B21+B22 (4.03/6.02)
trophy_unlock_persistence_check  = 1  // re-apply after SceShellCore respawn
```

---

## 8. Gotchas

### kstuff pause during DMAP writes

DMAP cross-process writes fail silently if kstuff is paused. Wrap all
DMAP ops :

```c
bool resumed = phu_kstuff_ctrl_temporary_resume_for_op();
// ... your DMAP write ...
phu_kstuff_ctrl_restore_after_op(resumed);
```

### kernel_mprotect after DMAP write

The CPU caches instruction decoding. DMAP write modifies memory but the
CPU cache can still serve the old decode. Always flush after :

```c
kernel_mprotect(target_pid, (intptr_t)(va & ~0xFFFUL), 0x1000, PROT_READ | PROT_EXEC);
```

### pt_detach SIGCONT pattern

On some jailbreak setups, `pt_detach(pid, 0)` leaves SceShellUI or the
game frozen in some scenarios. Correct pattern :

```c
pt_detach(pid, SIGCONT);
kill(pid, SIGCONT);  // double SIGCONT to flush libNineS internal state
```

### SceShellCore freeze on quick relaunch (fw 4.03)

Race condition between DMAP write and SceShellCore serving the launch
IPC. User workaround : wait 30-60s between 2 launches of the same game.
Code fix : TBD (delay + retry, or skip patches if recently applied).

### Game's natural register call timing

The game calls RegisterContext when ITS libSceUserService is init. On
games that boot fast (~15s), it's too early for B6 pt_call query. B6
fails cosmetically but the natural call fires ~5-30s later → install OK
anyway.

### PS4 BC games DO NOT hit the trophy chain

Sony's PS4 BC fpkg games use the native v1 trophy chain. The code detects
`CUSA*`/`BLES*`/`PCAS*` etc. titleids and skips immediately (via
`trophy_is_ps5_native()`). If you modify the entry point, keep this
guard.

### NPWR resolution from npbind.dat

`npbind.dat` is Sony-AES encrypted but the header is plain. The first
16 bytes contain magic `0xD294A018` + version + count. The NPWR plaintext
is extractable via TLV walk if needed for install detection.

