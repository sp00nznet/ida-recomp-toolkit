# IDA Recomp Toolkit

Headless **IDA Pro 9.x** tooling for **cross-validating static-recompilation
projects** — load a game binary at the recompiler's exact memory layout, let IDA
analyze it independently, and diff IDA's findings against the recomp's function
table to surface missed functions, bogus functions, and boundary disagreements —
plus generate aligned Hex-Rays pseudocode as a reference for the port.

Built against PSX (psxrecomp) and N64 (N64Recomp) projects, but the approach
generalizes to any recomp with a known function list.

> **No game data here.** ROMs, executables, IDA databases (`.i64`), and decompiled
> game code are `.gitignore`d — this repo is tooling, configs, and findings only.

---

## What's inside

```
setup/        Headless IDA setup: idalib + ida-pro-mcp, MCP config, launcher
tools/        The analysis scripts (idalib + idat.exe based)
  diagnostics/  Probes used to develop/verify the pipeline
handoffs/     Per-project findings written back to each recomp project
```

---

## 1. Setup (one-time)

Full detail in [`setup/IDA-HEADLESS.md`](setup/IDA-HEADLESS.md). Summary:

1. **IDA Pro 9.x** installed and launched once (license accepted).
2. **Python 3.11** (non–Microsoft-Store, for reliable native DLL loading).
3. **idalib** — IDA as a Python library (headless, no GUI):
   ```powershell
   # copy out of Program Files first (pip can't build in a read-only dir)
   pip install <copy-of>\IDA\idalib\python
   python <IDA>\idalib\python\py-activate-idalib.py -d "<IDA install dir>"
   python -c "import idapro; import ida_pro; print(ida_pro.IDA_SDK_VERSION)"
   ```
4. **ida-pro-mcp** (optional, for conversational use from an MCP client):
   ```powershell
   pip install ida-pro-mcp
   ```
   ⚠️ On Python < 3.12, patch `ida_pro_mcp/mcp-plugin.py` to import `TypedDict`
   from `typing_extensions` (pydantic requirement) — see IDA-HEADLESS.md.

### Two ways to drive IDA
- **idalib scripting** — `import idapro` first, then normal IDAPython. Best for
  batch analysis. Used by all the PSX scripts here.
- **idat.exe batch** — the classic text-mode runner. **Required for non-standard
  loads** (raw binary, custom processor/base) because idalib can't select
  non-default loaders (it throws internal error 30602). Used by all the N64 scripts.
- **MCP** — `setup/start-ida-mcp.ps1 <binary>` serves IDA tools over SSE; register
  `setup/.mcp.json` in your MCP client.

---

## 2. The core idea

A recomp project ships a **function list** (addresses + sizes, e.g. psxrecomp's
`RecompiledFuncs/func_<addr>` or N64Recomp's `symbols.toml`). The toolkit:

1. **Loads the binary at the recomp's true vram** so addresses line up.
2. **Seeds** IDA with the known functions (or lets IDA discover independently).
3. **Diffs** IDA vs the recomp:
   - functions IDA finds that the recomp **missed**,
   - "functions" the recomp emits that are actually **data**,
   - **boundary** disagreements (where the two split functions differently).
4. **Decompiles** high-value functions to **aligned** Hex-Rays C as port reference.

---

## 3. Running it

### PSX (psxrecomp) — binary auto-loads via the `PS-X EXE` loader
```powershell
py -3.11 tools\pepsiman_gap.py        <PSX-EXE> <project_dir> gap_worklist.csv
py -3.11 tools\pepsiman_decompile.py  <PSX-EXE> gap_worklist.csv <out_dir> [N]
py -3.11 tools\pepsiman_gap_addrs.py  <PSX-EXE> <project_dir> reverse_gap.csv
py -3.11 tools\pepsiman_followup.py   <PSX-EXE> <project_dir> <out_dir>
```

### N64 single-segment (N64Recomp, e.g. extremeg / podracer)
Code maps at one rom→vram delta `D`. Load via `idat.exe` with base `D>>4`, and
**mark code segments 64-bit** (R4300 ⇒ Hex-Rays uses the MIPS64 decompiler):
```powershell
idat.exe -A -Tbinary -pmipsb -b0x7FFFF40 `
  "-Stools\n64_analyze.py <project_dir> <out_dir>" <rom.z64>
```
`n64_analyze.py` auto-finds `symbols.toml` + the `*.recomp.toml`, seeds all
functions, finds gaps, checks boundaries, and decompiles.

### PC / x86 (VC6 PE, e.g. Crimson Skies)
Native PE — loads in IDA directly at its image base, so it aligns with the recomp's
addresses with no tricks. The scripts also apply VC6/MFC FLIRT signatures and do a
real **vtable scan** (critical for C++ games — call-graph discovery misses virtuals):
```powershell
py -3.11 tools\crimson_gap.py      <decrypted.exe> <config_dir> <out_dir>
py -3.11 tools\crimson_vtables.py  <decrypted.exe> <config_dir> <out_dir>
```

### N64 overlay games (e.g. pokemonsnap)
Overlays share vram (mutually exclusive at runtime) → no single base. The overlay
loader flat-loads, copies each section's ROM bytes to its true vram, and selects a
non-overlapping resident set:
```powershell
idat.exe -A -Tbinary -pmipsb -b0x0 `
  "-Stools\n64_overlay_analyze.py <project_dir> <out_dir> <symbols.toml>" <rom.z64>
```
To analyze a specific overlay, load `main` + that one overlay in its own database.

---

## 4. Tool reference

| Script | Purpose |
|---|---|
| `tools/analyze.py` | General idalib helper: info / funcs / imports / strings / decompile / disasm |
| `tools/pepsiman_gap.py` | Forward gap: IDA functions not yet recompiled, ranked by callers/size |
| `tools/pepsiman_decompile.py` | Decompile the high-value un-recompiled functions |
| `tools/pepsiman_gap_addrs.py` | Reverse gap: recomp addrs IDA doesn't see as functions; attempts recovery |
| `tools/pepsiman_followup.py` | Boundary validation + data-false-positive ID + decompile recovered funcs |
| `tools/n64_analyze.py` | Single-segment N64: seed `symbols.toml`, cross-validate, decompile |
| `tools/n64_overlay_analyze.py` | Overlay N64: per-section vram mapping + resident cross-validation |
| `tools/crimson_gap.py` | x86 PE: gap vs `functions.json` + VC6/MFC FLIRT naming |
| `tools/crimson_vtables.py` | x86 PE: vtable scan → virtual methods the recomp missed |
| `tools/diagnostics/*` | Load-alignment / decompiler / boundary probes used to build the above |

---

## 5. Findings so far

| Project | Platform | Recomp toolchain | IDA verdict |
|---|---|---|---|
| **pepsiman** | PSX | psxrecomp (auto-discovery) | **Bugs found** — 6 data emitted as functions, `ClipF` mis-typed as data, 146 boundary splits; 503 SDK names recovered |
| **extremeg** | N64 | N64Recomp (curated) | Clean — 0 missed, 8 IDA-only (likely jump-table targets) |
| **podracer** | N64 | N64Recomp | **Flawless** — 880/880, 0 discrepancies |
| **pokemonsnap** | N64 | N64Recomp | Clean resident layout; 18 overlays pending per-overlay runs |
| **crimsonskies** | PC x86 | custom (VC6/MFC) | **~770 missed C++ virtual methods** (discovery doesn't parse vtables); 347 FLIRT names; 3 data false-positives |

**Takeaway:** curated symbol files (N64Recomp) validate near-perfectly against IDA;
auto-discovery toolchains (psxrecomp, the Crimson Skies pipeline) had real, actionable
gaps — most strikingly, call-graph discovery on a C++ binary misses ~770 vtable-only
virtual methods that IDA recovers. Per-project detail and action items are in
[`handoffs/`](handoffs/).

---

## 6. Conventions

- Run scripts with **Python 3.11** (`py -3.11`) — the interpreter idalib is bound to.
- idat scripts must **not** `import idapro` (they already run inside IDA).
- Work on a **scratch copy** of the binary so the `.i64` doesn't land in the
  game-data tree.
- Outputs (`work/`, `*_summary.txt`, `*_reference.c`, `*.csv`) are git-ignored.
