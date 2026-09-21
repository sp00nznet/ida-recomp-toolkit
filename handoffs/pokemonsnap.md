# IDA Pro Cross-Validation — Pokémon Snap (N64)

Headless IDA Pro 9.1 analysis of `pokemonsnap.us.z64`, cross-checked against
`PokemonSnapSyms/dump.toml`.

## Pokémon Snap is overlay-based — special handling required

`dump.toml` has **25 sections with 25 different rom→vram deltas**. The course and
menu overlays (`beach/tunnel/cave/river/volcano/valley_code`, `oaks_lab`,
`photo_check`, menus, …) load into **overlapping vram** — they are mutually
exclusive at runtime and cannot coexist in one database.

**Loader** (`tools/n64_overlay_analyze.py`, via `idat -Tbinary -pmipsb -b0`):
flat-loads for a MIPS64 db, then copies each section's ROM bytes to its true vram,
greedily selecting a **non-overlapping** set (one consistent memory layout).

## Result on the resident layout ✅

| | |
|---|---|
| Sections mapped (resident) | **7** (`main`, `app_render`, `more_funcs`, `world`, `beach_code`, `app_level`, `camera_check`) |
| Sections skipped (overlay conflicts) | **18** (listed in `pokemonsnap_summary.txt`) |
| Functions seeded | **2375 / 2380** |
| IDA-only in resident ranges | 61, but **mostly false positives** — IDA mis-disassembling data in overlay-gap regions (e.g. repeated `movt $zero,$zero,$fcc0` at `0x8036Axxx`, where the non-resident `window` overlay would load). No clear real misses. |

`dump.toml`'s resident function coverage looks complete.

## To analyze the 18 skipped overlays
Each needs its **own** database: load `main` + exactly one overlay (so the shared
vram region holds that overlay's bytes). The loader can be pointed at a chosen
overlay set — straightforward extension of `n64_overlay_analyze.py`.

## Deliverable
`$IDA_WORK/pokemonsnap/decomp/_pokemonsnap_reference.c` (~180 KB) — MIPS64
pseudocode of the 15 largest resident functions, addresses matching the recomp.
