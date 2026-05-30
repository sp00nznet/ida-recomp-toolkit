#!/usr/bin/env python3
"""
Gap analysis for the pepsiman PSX recompilation.

Cross-references the functions IDA discovers in the PSX-EXE against the
functions psxrecomp has already emitted (RecompiledFuncs/func_<ADDR>) and the
project's known symbol names, then writes a prioritized worklist of functions
that still need recompiling (ranked by caller count, then size).

Usage:
    py -3.11 tools/pepsiman_gap.py <SLPS_017.62> <recomp_project_dir> <out.csv>

<recomp_project_dir> is the pepsiman project root (the one containing
RecompiledFuncs/ , config/ , symbols.txt).
"""
import sys, os, re, csv
import idapro  # first

import ida_auto, ida_funcs, ida_name, ida_bytes
import idautils, idc
import ida_xref

FUNC_DEF_RE = re.compile(r"\bfunc_([0-9A-Fa-f]{6,8})\s*\(\s*void\s*\)\s*\{")
SYM_RE = re.compile(r"^\s*(0x[0-9A-Fa-f]+)\s+(\S+)")


def load_recompiled(recomp_dir):
    """Addresses that already have a generated func_<ADDR> definition."""
    done = set()
    d = os.path.join(recomp_dir, "RecompiledFuncs")
    if not os.path.isdir(d):
        print(f"[!] no RecompiledFuncs dir at {d}", file=sys.stderr)
        return done
    for fn in os.listdir(d):
        if not fn.endswith(".c"):
            continue
        with open(os.path.join(d, fn), "r", encoding="utf-8", errors="replace") as f:
            for m in FUNC_DEF_RE.finditer(f.read()):
                done.add(int(m.group(1), 16))
    return done


def load_symbols(recomp_dir):
    """addr -> known name, from any symbols*.txt in root and config/."""
    names = {}
    candidates = [
        os.path.join(recomp_dir, "symbols.txt"),
        os.path.join(recomp_dir, "config", "pepsiman_symbols.txt"),
    ]
    for path in candidates:
        if not os.path.isfile(path):
            continue
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                m = SYM_RE.match(line)
                if m:
                    names[int(m.group(1), 16)] = m.group(2)
    return names


def caller_count(ea):
    """Number of distinct code references to this function's entry."""
    return sum(1 for _ in idautils.CodeRefsTo(ea, 1))


def main():
    if len(sys.argv) != 4:
        raise SystemExit(__doc__)
    binary, recomp_dir, out_csv = sys.argv[1:4]

    print(f"[*] Opening {binary} headless...", file=sys.stderr)
    if idapro.open_database(binary, run_auto_analysis=True):
        raise SystemExit("failed to open database")
    ida_auto.auto_wait()

    recompiled = load_recompiled(recomp_dir)
    known = load_symbols(recomp_dir)
    print(f"[*] recompiled funcs: {len(recompiled)} | known symbols: {len(known)}", file=sys.stderr)

    rows = []
    ida_eas = set()
    for ea in idautils.Functions():
        ida_eas.add(ea)
        f = ida_funcs.get_func(ea)
        size = f.end_ea - f.start_ea
        rows.append({
            "address": f"0x{ea:08X}",
            "name": known.get(ea, ida_name.get_name(ea)),
            "known_symbol": "yes" if ea in known else "no",
            "recompiled": "yes" if ea in recompiled else "no",
            "size_bytes": size,
            "callers": caller_count(ea),
        })

    todo = [r for r in rows if r["recompiled"] == "no"]
    todo.sort(key=lambda r: (-r["callers"], -r["size_bytes"]))

    with open(out_csv, "w", newline="", encoding="utf-8") as fp:
        w = csv.DictWriter(fp, fieldnames=["address", "name", "known_symbol",
                                           "recompiled", "size_bytes", "callers"])
        w.writeheader()
        w.writerows(todo)

    # recompiled addresses that IDA did NOT recognize as functions (sanity check)
    recompiled_not_in_ida = sorted(recompiled - ida_eas)

    print("\n================ GAP ANALYSIS: pepsiman ================")
    print(f"IDA functions total        : {len(rows)}")
    print(f"Already recompiled         : {sum(1 for r in rows if r['recompiled']=='yes')}")
    print(f"Still TODO                 : {len(todo)}")
    print(f"  of which have known names: {sum(1 for r in todo if r['known_symbol']=='yes')}")
    print(f"Recompiled but not seen by IDA as a func: {len(recompiled_not_in_ida)}")
    print(f"\nWorklist written to: {out_csv}")
    print("\nTop 20 TODO functions (by caller count, then size):")
    print(f"  {'ADDRESS':12} {'CALLERS':>7} {'SIZE':>7}  NAME")
    for r in todo[:20]:
        print(f"  {r['address']:12} {r['callers']:>7} {r['size_bytes']:>7}  {r['name']}")

    idapro.close_database(save=False)


if __name__ == "__main__":
    main()
