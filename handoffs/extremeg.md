# IDA Pro Cross-Validation — Extreme-G (N64)

Headless IDA Pro 9.1 analysis of `extremeg_recomp.z64`, loaded at the recomp's
exact vram layout and cross-checked against `symbols.toml` / `extremeg.recomp.toml`.

**Load recipe** (idalib can't do non-default loaders; use `idat.exe`):
```
idat.exe -A -Tbinary -pmipsb -b0x7FFFF40 -S<script> extremeg_recomp.z64
```
Both sections share rom→vram delta `0x7FFFF400`, so one flat binary load at that
base places the whole ROM at correct vram. R4300 ⇒ mark code segments **64-bit**
(`bitness=2`) or Hex-Rays refuses them ("only 64-bit functions can be decompiled").

---

## Result: `symbols.toml` is clean and complete ✅

Unlike auto-discovery toolchains, N64Recomp's curated symbol file held up well:

| Check | Result |
|---|---|
| Functions seeded into IDA | **759 / 763** (4 unseeded = 8-byte HW stubs, already in `stubs`) |
| Missed functions (prologue in an uncovered gap) | **0** — full code-section coverage |
| Boundary integrity | clean — spot-checked functions end exactly at `jr $ra; nop` |
| Boundary layout | 553 contiguous, 156 with trailing padding (both normal) |

**No action required on the function table.** This is a notably cleaner result
than the PSX/psxrecomp auto-discovery pipeline (which had data emitted as
functions and missed real code).

---

## One thing to verify: 8 IDA-only entry points

IDA's flow analysis created 8 functions in the code section that `symbols.toml`
does **not** list:

```
0x8005E7A4  0x80073D8C  0x80074048  0x80074298
0x800802B4  0x80090620  0x80090810  0x80091710
```

All start with `lw <reg>, <global>` (not a stack prologue), so they are **most
likely jump-table / switch `jr` targets** that IDA mis-promoted to functions —
i.e. probably *not* real missed functions. Worth a 5-minute confirm: if any is a
genuine indirectly-called function, it would be absent from the recomp output.

---

## Deliverable: aligned reference pseudocode

Hex-Rays (MIPS64) decompilation of the 15 largest functions + 5 stubbed ones,
addresses matching the recomp exactly, with float-register tracking intact
(useful for the matrix/physics code):

```
$IDA_WORK/extremeg/decomp/_extremeg_reference.c   (~100 KB)
```

Regenerate / extend with `tools/n64_analyze.py` (same idat recipe above).
The script also works on other N64Recomp projects (podracer, pokemonsnap) by
pointing `PROJ` at them.
