# IDA Pro Cross-Validation — Handoff & Action Items

Source: headless IDA Pro 9.1 (idalib) analysis of `SLPS_017.62`, cross-referenced
against `RecompiledFuncs/` and `config/`. IDA found **1156 functions** vs the
**1211** psxrecomp emits; this doc captures the differences worth acting on.

Generated 2026-05. Full data artifacts live at `E:\ida\work\pepsiman\`
(`gap_worklist.csv`, `reverse_gap.csv`, `task1_boundaries.csv`,
`task2_data_fp.csv`, `decomp/`, `recovered/`). The actionable subset is inlined
below so this file stands alone.

---

## TL;DR — three action items, by priority

| # | Type | Action |
|---|------|--------|
| 1 | 🐛 **Bug** | Stop emitting `func_<addr>` for 6 **data** addresses (linear-sweep over-reach). |
| 2 | ✨ **Enhance** | Adopt IDA's **503 recovered PsyQ SDK symbol names** (project currently names ~182). |
| 3 | ✅ **Validated** | Function boundaries are correct — no action, but eyeball one region. |

---

## 1. 🐛 BUG: data emitted as functions

psxrecomp generates `func_<addr>` for **6 addresses that are data, not code**.
IDA classifies all 6 as data; none have any incoming call/jump xref; none are in
`config/pepsiman_symbols.txt`. They are reached by psxrecomp's own linear sweep
walking past the last real function into embedded/trailing data:

```
0x8007D5AC   .word 0, 0, 0, 0, ...            (zero-fill table)
0x80080024   .word 0xFFFA1000, 0xFFF31000, …  (constant table, ~ -0x7000 stride)
0x8008002C   .word 0xFFFA1000, …                "
0x80080030   .word 0xFFFA1000, …                "
0x80080034   .word 0xFFFA1000, …                "
0x80095800   .space 4                          (= load_addr 0x80010000 + code_size
                                                 0x85800 → exact code/data boundary)
```

These will compile into garbage "functions." 

**Recommended fix (root cause):** psxrecomp's discovery accepts a candidate with
no incoming reference *and* no valid prologue. Add a validation filter to the
function-discovery pass:

> Accept an auto-discovered function only if **either** (a) it is the target of a
> `jal`/`j`/branch, **or** (b) its first instruction is a recognizable prologue
> (e.g. `addiu $sp, $sp, -N`). Reject candidates that are neither.

All 6 false-positives fail both tests, so this filter removes them while keeping
every legitimate function (the 146 indirectly-reached real functions below all
have valid prologues and/or jump refs, so they survive).

**Quick fix (unblock now):** mark the code/data boundary in `pepsiman.toml` so the
sweep stops at the rodata. The real code ends well before `0x8007D5AC`; treat
`0x8007D5AC … end` as data.

---

## 2. ✨ ENHANCE: 503 recovered symbol names

IDA's signature analysis named **503** of the 1156 functions — almost all PsyQ
SDK routines (`SsInit`, `SpuInit`, the whole `_spu_*` family, `__muldf3` and the
soft-float runtime, `CD_*`, `Gs*`, `ClipF`, …). `config/pepsiman_symbols.txt`
currently has ~182. The full address→name list is provided alongside this doc:

```
docs/ida_named_functions.txt      # 503 entries, "0xADDR  name"
```

Merge the ones you don't already have into `config/pepsiman_symbols.txt` to get
meaningful names instead of `func_<addr>` across most of the SDK surface. (These
are IDA FLIRT/library matches — high confidence, but spot-check before bulk
import.)

---

## 3. ✅ VALIDATED: function boundaries are correct

There are **146** addresses psxrecomp treats as functions that fall *inside* a
single IDA function (i.e. psxrecomp splits finer than IDA). This is **not** a
psxrecomp error — it's the opposite. Of the 146:

- **120 / 146** begin with a valid stack prologue (`addiu $sp, -N`) → real entries.
- **0** are reached by a `jal` (call) → which is exactly why IDA's flow analysis
  merged them; they're reached only by tail-call (`j`, 12) or indirectly via
  function pointers / jump tables (134). psxrecomp is **right** to split them —
  each needs its own translated unit.

**Conclusion:** psxrecomp's boundaries are more accurate than IDA's auto-analysis
here. No action required.

One spot worth a manual glance: IDA glues **13** psxrecomp functions into the
single function at **`0x8003FFAC`** (the most-merged region) — likely a chain of
tail-called handlers. Confirm psxrecomp split it sensibly there.

Also note: **`ClipF` @ `0x80055644`** (a real ~430-instruction libgte clipping
routine) is correctly emitted by psxrecomp but was mis-classified as *data* by
IDA — a point in psxrecomp's favor. No action; cross-check only.

---

## How to regenerate / extend

The analysis is fully scripted and headless (no IDA GUI). Scripts:
`E:\ida\tools\pepsiman_gap.py`, `pepsiman_decompile.py`, `pepsiman_gap_addrs.py`,
`pepsiman_followup.py`. Re-run any after psxrecomp changes to re-measure the gap.
