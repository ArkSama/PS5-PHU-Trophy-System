# PHU Trophy System

PS5 trophy install + unlock for dumped games. Works offline, local-only.

This is the trophy system code extracted from the PHU Games Tools payload.
If you have a jailbroken PS5 on fw 4.03 -> 12.70 (PS5 Pro), this lets you
install trophies for a dumped game so they show up in your profile.

---

## What it does

When you dump a PS5 game and launch it, Sony's trophy daemon refuses to
register the context because the NPWR / commId / signature don't match a
properly installed PKG.

This code patches the SceShellCore daemon (userland via DMAP cross-process)
to bypass Sony's checks and register the context naturally. Once the
context is registered, trophy unlocks work just like a PSN-installed game
(cmd 0x9004a libSceNpTrophy.sprx).

---

## Supported firmwares

24 firmwares now, byte-exact per fw:

```
4.03  4.50  4.51  5.02  5.50  6.02  6.50  7.20  7.40  7.60
7.61  8.00  9.00  9.40  9.60  10.00 10.01 10.20 11.00 11.20
11.60 12.00 12.40 12.70 (PS5 Pro)
```

By generation:
- pre-Cronos: 4.03, 4.50, 4.51, 5.02, 5.50, 6.02, 6.50, 7.20, 7.40, 7.60, 7.61, 8.00, 9.00, 9.40, 9.60
- Cronos (Sony refactor 10.x+): 10.00, 10.01, 10.20, 11.00, 11.20, 11.60, 12.00, 12.40
- PS5 Pro Cronos: 12.70

4.x range is mostly the early launch firmwares. Sony's NPWR / RecoveryRequired bug
in the launch fw (`IsDeprecatedVersion` always returns TRUE when version field == 0x10000)
is handled by the B20/B21/B22 trio. On 4.03 it's enabled by default. On 4.50 / 4.51
the patches are present but DISABLED — flip `trophy_summary_bypass_enabled = 1` in
the cfg if you see "trophies show in profile but unlock fail in-game".

---

## Architecture

The system is made of "B-patches" (each patch has a name: B1, B3, B4,
B5_LNC, etc.) applied at different points depending on firmware:

| Patch | What | Where |
|---|---|---|
| B1 | Replaces 4x strings `AAAA00000` -> `ZZZZZZZZZ` | SceShellCore .rodata |
| B2 | Inject NpAsmClient cache (commId/secret/flags) | libSceNpManager DAT singleton |
| B3 | Crypto bypass / file loader sabotage disable | SceShellCore |
| B4 | App inventory bypass | SceShellCore |
| B5_LNC | LncManager attr gate NOP | SceShellCore |
| B6 | pt_call `sceNpTrophy2RegisterContext` | game process (libSceNpTrophy2) |
| B7 | Copy `npbind.dat` + `trophy00.ucp` to `/system_data/priv/appmeta/<TID>/` | FS |
| B11 | Force `SceNpBindLocal` init (Cronos only) | SceShellCore |
| B13/B14/B15 | User::GetUser, IsLoggedIn, IsGuest bypass (Cronos era) | libSceNpManager |
| B16 | user_status normalizer (10.01) | SceShellCore |
| B17 | 4x `MOV R15D, 0x8055391e` bypass (10.01 cascade fix) | SceShellCore |
| B18 | Force first-time path in orchestrator (10.01) | SceShellCore |
| B20 | IsDeprecatedVersion bypass (4.03 launch fw bug fix) | SceShellCore |
| B21 | RecoveryRequired setter disable | SceShellCore |
| B22 | RecoveryRequired reader bypass (companion to B21) | SceShellCore |

Not all patches are active on all fws — each firmware has its own config
in the `g_trophy_fw_table[]` table at the top of `phu_trophy.cpp`.

### General flow

```
boot payload
  -> probe scan allproc to detect PS5 native game (PPSA*/PPSB*)
  -> game caught
  -> apply_per_game(game_pid, titleid)
       ├─ lazy_init_boot  -> SceShellCore patches (B1+B3+B4+B5_LNC + per-fw extras)
       ├─ B7  setup_appmeta : copy trophy files into canonical daemon path
       ├─ B2  NpAsmClient inject : write title + flags into the game-side lib
       └─ B6  force-install : pt_call CreateContext + CreateHandle + RegisterContext
  -> game runs, trophy unlocks work normally
  -> game vanish
  -> rollback_boot : restore SceShellCore vanilla (= PS4 BC games launch fine after)
```

---

## Why rollback at game vanish

If B1+B3+B4+B5_LNC stay active on SceShellCore permanently, the next
launch of a PS4 BC game (properly fpkg-installed) hits
`sceNpTrophyVshPromoteCheckRecoveryRequired2` which returns 0x80551618
because the B1 patches modify the strings that Sony's NPDRM check uses to
decide whether to invalidate the license. Result: NPDRM deletes the
license, the game launch is aborted.

Rollback at game vanish restores SceShellCore to vanilla, so:
- PS5 native dump -> patches active during session -> trophy install OK
- PS4 BC fpkg -> vanilla SceShellCore -> Sony's promote chain OK -> game launch OK

Polyvalent in the same session, no reboot needed.

---

## Multi-user

The full chain is re-applied at every game cycle. So:

```
user1 launches game     -> patches OK -> trophy install user1
user1 quits             -> rollback   -> vanilla
user2 launches same game -> patches re-applied -> trophy install user2
```

Foreground user is resolved via `sceUserServiceGetForegroundUser` (PRIMARY),
falling back through `sceNpUserGetUserIdList`, `sceUserServiceGetInitialUser`,
`sceUserServiceGetLoginUserIdList`, and last resort scan of `/user/home/`.

---

## Files

```
src/
├── phu_trophy.cpp       <- main implementation (~5600 lines, 24 fws + patches)
├── phu_trophy.h         <- public API
├── phu_fw_offsets.c     <- per-fw kernel offsets table (41 fws total, kstuff + trophy)
└── phu_fw_offsets.h     <- phu_fw_offsets API
```

Depends on:
- `libhijacker` (DMAP cross-process: kernel_copyout/kernel_copyin)
- `libNineS` (proc lookup, ptrace wrappers)
- ps5-payload-dev SDK (compile + link)

Extracted from the PHU Games Tools payload — this code alone won't compile
without those deps. It serves more as RE reference than a drop-in lib.

---

## How to use it

3 use cases:

1. RE reference for future payloads: if you're writing a trophy install
   payload for an unsupported firmware, you can base your work on the
   patterns here (B-patches structure, anchor -> DAT pattern, etc.).
2. Reproduce in your custom payload: copy-paste the byte-exact VAs for
   your fw, adapt the API to your SDK.
3. Understand Sony's system: the comments at the top of each file explain
   how Sony's Trophy 2 daemon works, call chains, error codes, what each
   patch does.

See [WORKFLOW.md](WORKFLOW.md) for the full architecture.

---

## Credits

- Arksama (Team PHU) — RE + implementation + maintenance
- Team PHU — Hyndrid, NewRival, Lestat, Markus95, Link to the Games Dz

Standing on the shoulders of:
- EchoStretch — kstuff
- illusion + LightingMod — libhijacker
- John Tornblom — ps5-payload-dev / libNineS
- Sleirsgoevy, theflow, Specter — early PS5 research
- PlayStation Hackers United community

---

## License

MIT — see [LICENSE](LICENSE).

Use it however you want, but credit if you reuse. No warranty, no
guarantee, if you brick your console it's on you.

---

## Notes

- This is RE work on jailbroken Sony fw, for educational + interop purposes.
- Local-only: DO NOT sync trophy unlocks to PSN with your main account,
  Sony may ban.
- Patches are firmware-specific, byte-exact verified. If you run on an
  unsupported fw, the code skips cleanly (`fw not supported`).

Team PHU Discord for code feedback.
