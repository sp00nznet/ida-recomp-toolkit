#!/usr/bin/env python3
"""
Decompile the high-value un-recompiled functions from the gap worklist.

Reads gap_worklist.csv, selects the genuine static-recomp candidates
(unnamed sub_* entries, i.e. not PSX-SDK/HLE functions), ranks them by
caller count then size, and decompiles the top N to Hex-Rays pseudocode --
one .c per function plus a combined reference file.

Usage:
    py -3.11 tools/pepsiman_decompile.py <binary> <gap_worklist.csv> <out_dir> [N]
"""
import sys, os, csv
import idapro  # first

import ida_auto, ida_funcs, ida_hexrays, ida_name


def main():
    if len(sys.argv) < 4:
        raise SystemExit(__doc__)
    binary, csv_path, out_dir = sys.argv[1:4]
    limit = int(sys.argv[4]) if len(sys.argv) > 4 else 25
    os.makedirs(out_dir, exist_ok=True)

    # pick targets from the worklist: unnamed recomp candidates, ranked
    with open(csv_path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    cand = [r for r in rows if r["name"].startswith("sub_")]
    cand.sort(key=lambda r: (-int(r["callers"]), -int(r["size_bytes"])))
    targets = cand[:limit]
    print(f"[*] {len(cand)} sub_* candidates; decompiling top {len(targets)}", file=sys.stderr)

    print(f"[*] Opening {binary} headless...", file=sys.stderr)
    if idapro.open_database(binary, run_auto_analysis=True):
        raise SystemExit("failed to open database")
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        raise SystemExit("Hex-Rays not available")

    combined = os.path.join(out_dir, "_reference.c")
    results = []
    with open(combined, "w", encoding="utf-8") as ref:
        ref.write("/* Hex-Rays reference pseudocode for un-recompiled pepsiman functions */\n\n")
        for r in targets:
            ea = int(r["address"], 16)
            f = ida_funcs.get_func(ea)
            name = ida_name.get_name(ea)
            try:
                code = str(ida_hexrays.decompile(f))
                status = "ok"
            except Exception as e:
                code = f"/* decompile failed: {e} */\n"
                status = "FAIL"
            header = (f"/* ==== {name} @ {r['address']}  "
                      f"callers={r['callers']} size={r['size_bytes']} ==== */\n")
            ref.write(header + code + "\n\n")
            with open(os.path.join(out_dir, f"{name}.c"), "w", encoding="utf-8") as one:
                one.write(header + code + "\n")
            nlines = code.count("\n")
            results.append((name, r["address"], r["callers"], r["size_bytes"], status, nlines))
            print(f"  {status:4} {r['address']}  {name}  ({nlines} lines)", file=sys.stderr)

    ok = sum(1 for x in results if x[4] == "ok")
    print(f"\n[*] Decompiled {ok}/{len(results)} OK")
    print(f"[*] Combined reference: {combined}")
    print(f"[*] Per-function files in: {out_dir}")
    print("\n  STATUS  ADDRESS      CALLERS  SIZE  LINES  NAME")
    for name, addr, callers, size, status, nlines in results:
        print(f"  {status:6} {addr}  {callers:>7}  {size:>4}  {nlines:>5}  {name}")

    idapro.close_database(save=False)


if __name__ == "__main__":
    main()
