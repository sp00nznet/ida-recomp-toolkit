#!/usr/bin/env python3
"""
Crimson Skies (x86 PE) cross-validation against the recomp's function list.

  py -3.11 tools/crimson_gap.py <decrypted.exe> <project_config_dir> <out_dir>

Compares IDA's independent function discovery (+ FLIRT library naming) against
config/functions.json (+ manual_functions.json):
  - IDA-only  : functions IDA found that the recomp MISSED
  - recomp-only: recomp addresses IDA does NOT see as a function (data / false pos)
  - named     : IDA FLIRT-identified names (CRT/MFC42/...) to enrich the recomp's sub_ labels
"""
import sys, os, json, csv
import idapro  # first

import ida_auto, ida_funcs, ida_name, ida_bytes, ida_hexrays, idautils, idc, ida_lines, ida_ida

GENERIC = ("sub_", "nullsub_", "loc_", "unknown_", "j_")


def is_named(n):
    return n and not n.startswith(GENERIC)


def load_json_addrs(path):
    if not os.path.isfile(path):
        return {}, []
    data = json.load(open(path, encoding="utf-8"))
    rows = data if isinstance(data, list) else list(data.values())
    m = {}
    for r in rows:
        ea = r.get("address_int") or int(r["address"], 16)
        m[ea] = r.get("name", "")
    return m, rows


def main():
    exe, cfg_dir, out_dir = sys.argv[1:4]
    os.makedirs(out_dir, exist_ok=True)
    print(f"[*] opening {exe} ...", file=sys.stderr)
    if idapro.open_database(exe, run_auto_analysis=True):
        raise SystemExit("open failed")
    ida_auto.auto_wait()

    # Apply VC6 / MFC42 FLIRT signatures explicitly (auto-analysis only applies a subset)
    for sig in ("vc32rtf", "vc32mfc", "vc32mfce", "omvc60", "vcseh", "vcextra", "vc32ucrt"):
        ida_funcs.plan_to_apply_idasgn(sig)
    ida_auto.auto_wait()

    recomp, _ = load_json_addrs(os.path.join(cfg_dir, "functions.json"))
    manual, _ = load_json_addrs(os.path.join(cfg_dir, "manual_functions.json"))
    print(f"[*] recomp functions.json={len(recomp)} manual={len(manual)}", file=sys.stderr)

    ida = {}
    for ea in idautils.Functions():
        ida[ea] = ida_name.get_name(ea)

    ida_set, rec_set = set(ida), set(recomp)
    ida_only = sorted(ida_set - rec_set)            # recomp MISSED
    recomp_only = sorted(rec_set - ida_set)         # IDA: not a function (data / false pos)
    named = {ea: n for ea, n in ida.items() if is_named(n)}

    # Break down the "missed" set honestly. This is a C++/MFC binary, so:
    #  - library funcs (FLIRT/FUNC_LIB) are handled by the host CRT/MFC, NOT real misses
    #  - app funcs reached via vtable/func-ptr show DATA refs, not code refs
    def has_code_ref(ea): return any(True for _ in idautils.CodeRefsTo(ea, 0))
    def has_data_ref(ea): return any(True for _ in idautils.DataRefsTo(ea))
    def is_lib(ea):
        f = ida_funcs.get_func(ea)
        return bool(f and (f.flags & ida_funcs.FUNC_LIB)) or is_named(ida.get(ea, ""))
    miss_lib = miss_called = miss_vtable = miss_noref = 0
    real_missed = []
    for ea in ida_only:
        if is_lib(ea):
            miss_lib += 1
        elif has_code_ref(ea):
            miss_called += 1; real_missed.append(ea)
        elif has_data_ref(ea):
            miss_vtable += 1; real_missed.append(ea)
        else:
            miss_noref += 1

    # characterize recomp-only: is it code IDA put inside another func, or data?
    def classify(ea):
        if not ida_bytes.is_mapped(ea): return "unmapped"
        f = ida_funcs.get_func(ea)
        if f and f.start_ea != ea: return "mid_function"
        if ida_bytes.is_code(ida_bytes.get_flags(ea)): return "code_orphan"
        return "data"
    ro_class = {}
    for ea in recomp_only:
        c = classify(ea); ro_class[c] = ro_class.get(c, 0) + 1

    # write artifacts
    with open(os.path.join(out_dir, "crimson_ida_only.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(["address", "ida_name", "kind", "disasm"])
        for ea in ida_only:
            kind = ("library" if is_lib(ea) else "called" if has_code_ref(ea)
                    else "vtable" if has_data_ref(ea) else "noref")
            w.writerow([f"0x{ea:08X}", ida[ea], kind,
                        ida_lines.tag_remove(idc.generate_disasm_line(ea, 0) or "")])
    with open(os.path.join(out_dir, "crimson_recomp_only.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(["address", "recomp_name", "ida_classification", "disasm"])
        for ea in recomp_only:
            w.writerow([f"0x{ea:08X}", recomp.get(ea, ""), classify(ea),
                        ida_lines.tag_remove(idc.generate_disasm_line(ea, 0) or "") if ida_bytes.is_mapped(ea) else ""])
    with open(os.path.join(out_dir, "crimson_ida_names.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(["address", "ida_name", "in_recomp_named"])
        for ea in sorted(named):
            rn = recomp.get(ea, "")
            w.writerow([f"0x{ea:08X}", named[ea], "yes" if is_named(rn) else "no"])

    new_names = sum(1 for ea in named if not is_named(recomp.get(ea, "")))
    log = []
    a = log.append
    a("================ CRIMSON SKIES GAP ANALYSIS ================")
    a(f"IDA functions             : {len(ida)}")
    a(f"recomp functions.json     : {len(recomp)}  (+ manual {len(manual)})")
    a(f"overlap                   : {len(ida_set & rec_set)}")
    a(f"IDA-only (IDA found, not in recomp): {len(ida_only)}")
    a(f"   - library (host-handled, not a miss) : {miss_lib}")
    a(f"   - REAL app misses (called)           : {miss_called}")
    a(f"   - REAL app misses (vtable/func-ptr)  : {miss_vtable}")
    a(f"   - app, no reference (indirect/noise) : {miss_noref}")
    a(f"   => actionable real misses            : {len(real_missed)}")
    a(f"recomp-only (not a func)  : {len(recomp_only)}  -> {ro_class}")
    a(f"IDA named (FLIRT etc.)    : {len(named)}")
    a(f"  of which recomp has as sub_/unnamed (NEW names to adopt): {new_names}")
    a(f"Hex-Rays available        : {ida_hexrays.init_hexrays_plugin()}")
    a("")
    a("sample IDA-only (recomp missed) — first 15:")
    for ea in ida_only[:15]:
        a(f"   0x{ea:08X}  {ida[ea]}  | {ida_lines.tag_remove(idc.generate_disasm_line(ea,0) or '')}")
    a("")
    a("sample IDA FLIRT names (library funcs) — first 20:")
    for ea in sorted(named)[:20]:
        a(f"   0x{ea:08X}  {named[ea]}")
    open(os.path.join(out_dir, "crimson_summary.txt"), "w", encoding="utf-8").write("\n".join(log))
    print("\n".join(log))
    idapro.close_database(save=False)


if __name__ == "__main__":
    main()
