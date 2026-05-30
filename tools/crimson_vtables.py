#!/usr/bin/env python3
"""
Precise C++ vtable analysis for an x86 PE recomp.

  py -3.11 tools/crimson_vtables.py <decrypted.exe> <config_dir> <out_dir>

Scans read-only data for real vtables (runs of >=3 consecutive pointers that each
land on a function start), collects the virtual methods, and reports which ones
are MISSING from the recomp's functions.json -- the precise, defensible count of
virtual methods the recomp's call-graph discovery failed to capture.
"""
import sys, os, json, csv
import idapro

import ida_auto, ida_bytes, ida_funcs, ida_segment, idautils, idc, ida_name, ida_hexrays

MIN_RUN = 3  # minimum consecutive function pointers to count as a vtable


def load_recomp(cfg_dir):
    p = os.path.join(cfg_dir, "functions.json")
    data = json.load(open(p, encoding="utf-8"))
    rows = data if isinstance(data, list) else list(data.values())
    return {r.get("address_int") or int(r["address"], 16) for r in rows}


def main():
    exe, cfg_dir, out_dir = sys.argv[1:4]
    os.makedirs(out_dir, exist_ok=True)
    if idapro.open_database(exe, run_auto_analysis=True):
        raise SystemExit("open failed")
    ida_auto.auto_wait()

    recomp = load_recomp(cfg_dir)
    func_start = lambda d: (lambda f: bool(f) and f.start_ea == d)(ida_funcs.get_func(d))

    vtables = []          # (vtable_ea, [targets])
    vtable_targets = set()
    for i in range(ida_segment.get_segm_qty()):
        s = ida_segment.getnseg(i)
        if ida_segment.get_segm_class(s) == "CODE":
            continue
        ea = (s.start_ea + 3) & ~3
        while ea <= s.end_ea - 4:
            run, p = [], ea
            while p <= s.end_ea - 4:
                d = ida_bytes.get_dword(p)
                if 0x400000 <= d < 0x700000 and ida_bytes.is_mapped(d) and func_start(d):
                    run.append(d); p += 4
                else:
                    break
            if len(run) >= MIN_RUN:
                vtables.append((ea, run)); vtable_targets.update(run)
                ea = p
            else:
                ea += 4

    missed = sorted(t for t in vtable_targets if t not in recomp)
    present = len(vtable_targets) - len(missed)

    with open(os.path.join(out_dir, "crimson_missed_virtuals.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(["address", "ida_name", "disasm"])
        for ea in missed:
            w.writerow([f"0x{ea:08X}", ida_name.get_name(ea),
                        idc.generate_disasm_line(ea, 0) or ""])

    hx = ida_hexrays.init_hexrays_plugin()
    log = []; a = log.append
    a("================ CRIMSON SKIES — VTABLE ANALYSIS ================")
    a(f"vtables found (>= {MIN_RUN} consecutive fn-pointers) : {len(vtables)}")
    a(f"distinct virtual methods (vtable targets)        : {len(vtable_targets)}")
    a(f"  already in recomp functions.json               : {present}")
    a(f"  MISSING from recomp (missed virtual methods)   : {len(missed)}")
    a("")
    a("sample missed virtual methods (decompiled head):")
    shown = 0
    for ea in missed:
        if shown >= 6:
            break
        if hx:
            try:
                cf = str(ida_hexrays.decompile(ida_funcs.get_func(ea)))
                head = cf.splitlines()[0] if cf and cf != "None" else "(no output)"
            except Exception:
                head = "(decompile failed)"
        else:
            head = idc.generate_disasm_line(ea, 0) or ""
        a(f"   0x{ea:08X}  {ida_name.get_name(ea)}  | {head}")
        shown += 1
    open(os.path.join(out_dir, "crimson_vtables_summary.txt"), "w", encoding="utf-8").write("\n".join(log))
    print("\n".join(log))
    idapro.close_database(save=False)


if __name__ == "__main__":
    main()
