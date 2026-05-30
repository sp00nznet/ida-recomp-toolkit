#!/usr/bin/env python3
"""
Resolve the "reverse gap": addresses psxrecomp emitted as func_<ADDR> that IDA
did NOT auto-detect as function entries. Classify each, attempt recovery by
forcing IDA to create a function, and report what IDA had missed.

Usage:
    py -3.11 tools/pepsiman_gap_addrs.py <binary> <recomp_project_dir> <out.csv>
"""
import sys, os, re, csv
import idapro  # first

import ida_auto, ida_funcs, ida_bytes, ida_name, idautils, ida_segment, idc

FUNC_DEF_RE = re.compile(r"\bfunc_([0-9A-Fa-f]{6,8})\s*\(\s*void\s*\)\s*\{")


def load_recompiled(recomp_dir):
    done = set()
    d = os.path.join(recomp_dir, "RecompiledFuncs")
    for fn in os.listdir(d):
        if fn.endswith(".c"):
            with open(os.path.join(d, fn), encoding="utf-8", errors="replace") as f:
                for m in FUNC_DEF_RE.finditer(f.read()):
                    done.add(int(m.group(1), 16))
    return done


def classify(ea):
    if not ida_bytes.is_mapped(ea):
        return "not_mapped"          # BIOS / kernel / HLE stub address
    f = ida_funcs.get_func(ea)
    if f and f.start_ea != ea:
        return "mid_function"        # falls inside another IDA function (boundary differs)
    if f and f.start_ea == ea:
        return "already_func"        # shouldn't happen (filtered), but guard
    flags = ida_bytes.get_flags(ea)
    if ida_bytes.is_code(flags):
        return "code_orphan"         # code IDA never wrapped in a function
    if ida_bytes.is_unknown(flags):
        return "unknown_bytes"       # undefined - may be unconverted code
    return "data"                    # IDA thinks it's data


def disasm(ea):
    if not ida_bytes.is_mapped(ea):
        return ""
    return idc.generate_disasm_line(ea, 0) or ""


def main():
    if len(sys.argv) != 4:
        raise SystemExit(__doc__)
    binary, recomp_dir, out_csv = sys.argv[1:4]

    print(f"[*] Opening {binary} headless...", file=sys.stderr)
    if idapro.open_database(binary, run_auto_analysis=True):
        raise SystemExit("failed to open database")
    ida_auto.auto_wait()

    recompiled = load_recompiled(recomp_dir)
    ida_funcs_set = set(idautils.Functions())
    gap = sorted(recompiled - ida_funcs_set)
    print(f"[*] reverse-gap addresses: {len(gap)}", file=sys.stderr)

    # pass 1: classify as-found
    rows = []
    for ea in gap:
        rows.append({
            "address": f"0x{ea:08X}",
            "before": classify(ea),
            "name_before": ida_name.get_name(ea) or "",
            "disasm": ida_bytes.tag_remove(disasm(ea)) if hasattr(ida_bytes, "tag_remove") else disasm(ea),
        })

    # pass 2: attempt recovery on anything mapped that isn't already inside a
    # function. For data/unknown bytes, first undefine and force-decode as code
    # (catches real functions IDA mis-parked as data, e.g. indirectly-called ones).
    recovered = 0
    for r in rows:
        ea = int(r["address"], 16)
        if r["before"] in ("not_mapped", "mid_function", "already_func"):
            r["recovered"] = "n/a"
            continue
        if not ida_bytes.is_code(ida_bytes.get_flags(ea)):
            ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, 4)
            idc.create_insn(ea)
        ok = ida_funcs.add_func(ea)
        r["recovered"] = "yes" if ok else "no"
        if ok:
            recovered += 1
    if recovered:
        ida_auto.auto_wait()

    # pass 3: re-classify after recovery
    for r in rows:
        ea = int(r["address"], 16)
        f = ida_funcs.get_func(ea)
        r["after"] = "func" if (f and f.start_ea == ea) else classify(ea)
        r["name_after"] = ida_name.get_name(ea) or ""

    with open(out_csv, "w", newline="", encoding="utf-8") as fp:
        w = csv.DictWriter(fp, fieldnames=["address", "before", "recovered", "after",
                                           "name_after", "disasm"])
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in
                        ["address", "before", "recovered", "after", "name_after", "disasm"]})

    def tally(key):
        out = {}
        for r in rows:
            out[r[key]] = out.get(r[key], 0) + 1
        return dict(sorted(out.items(), key=lambda kv: -kv[1]))

    print("\n=========== REVERSE-GAP RESOLUTION: 157 addresses ===========")
    print(f"Total reverse-gap addresses : {len(rows)}")
    print(f"\nClassification BEFORE recovery:")
    for k, v in tally("before").items():
        print(f"   {k:14}: {v}")
    print(f"\nForced-function recovery     : {recovered} now recognized as functions by IDA")
    print(f"\nClassification AFTER recovery:")
    for k, v in tally("after").items():
        print(f"   {k:14}: {v}")
    print(f"\nFull breakdown written to: {out_csv}")
    print("\nSample of recovered functions (IDA had missed real code):")
    shown = 0
    for r in rows:
        if r.get("recovered") == "yes":
            print(f"   {r['address']}  {r['disasm']}")
            shown += 1
            if shown >= 15:
                break

    idapro.close_database(save=False)


if __name__ == "__main__":
    main()
