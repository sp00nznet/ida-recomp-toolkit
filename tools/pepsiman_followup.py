#!/usr/bin/env python3
"""
Follow-up analysis for pepsiman, three tasks in one IDA session:

  1. Boundary validation: for the ~146 reverse-gap addresses that fall inside an
     existing IDA function, determine WHY IDA merged them -- are they call (jal)
     targets, jump/tail-call targets, or fallthrough-only -- and group by the
     IDA function that psxrecomp splits further. Confirms whether psxrecomp's
     extra boundaries are legitimate.
  2. Data false-positives: for the addresses psxrecomp emitted as functions but
     IDA sees as data, show what references them (e.g. jump tables) to explain
     the mis-identification.
  3. Decompile the genuinely-missed functions IDA had not recognized, after
     forcing function creation.

Usage:
    py -3.11 tools/pepsiman_followup.py <binary> <recomp_project_dir> <out_dir>
"""
import sys, os, re, csv
import idapro  # first

import ida_auto, ida_funcs, ida_bytes, ida_name, ida_xref, ida_hexrays, ida_lines
import idautils, idc

FUNC_DEF_RE = re.compile(r"\bfunc_([0-9A-Fa-f]{6,8})\s*\(\s*void\s*\)\s*\{")
CALL_TYPES = {ida_xref.fl_CN, ida_xref.fl_CF}
JUMP_TYPES = {ida_xref.fl_JN, ida_xref.fl_JF}


def load_recompiled(recomp_dir):
    done = set()
    d = os.path.join(recomp_dir, "RecompiledFuncs")
    for fn in os.listdir(d):
        if fn.endswith(".c"):
            with open(os.path.join(d, fn), encoding="utf-8", errors="replace") as f:
                for m in FUNC_DEF_RE.finditer(f.read()):
                    done.add(int(m.group(1), 16))
    return done


def dis(ea):
    return ida_lines.tag_remove(idc.generate_disasm_line(ea, 0) or "")


def ref_breakdown(ea):
    """Count incoming code xrefs by kind."""
    calls = jumps = other = 0
    callers = []
    for xr in idautils.XrefsTo(ea, 0):
        if xr.iscode:
            if xr.type in CALL_TYPES:
                calls += 1; callers.append((xr.frm, "call"))
            elif xr.type in JUMP_TYPES:
                jumps += 1; callers.append((xr.frm, "jump"))
            else:
                other += 1
    return calls, jumps, other, callers


def main():
    if len(sys.argv) != 4:
        raise SystemExit(__doc__)
    binary, recomp_dir, out_dir = sys.argv[1:4]
    os.makedirs(out_dir, exist_ok=True)

    print(f"[*] Opening {binary} headless...", file=sys.stderr)
    if idapro.open_database(binary, run_auto_analysis=True):
        raise SystemExit("failed to open database")
    ida_auto.auto_wait()
    ida_hexrays.init_hexrays_plugin()

    recompiled = load_recompiled(recomp_dir)
    ida_set = set(idautils.Functions())
    gap = sorted(recompiled - ida_set)

    mid, data_fp, orphan = [], [], []
    for ea in gap:
        if not ida_bytes.is_mapped(ea):
            continue
        f = ida_funcs.get_func(ea)
        if f and f.start_ea != ea:
            mid.append(ea)
        elif ida_bytes.is_code(ida_bytes.get_flags(ea)):
            orphan.append(ea)
        else:
            data_fp.append(ea)

    # ---------- TASK 1: boundary validation ----------
    print("\n=============== TASK 1: boundary validation ===============")
    is_prologue = jal = jonly = noref = 0
    by_container = {}
    t1_rows = []
    for ea in mid:
        d = dis(ea)
        prologue = bool(re.search(r"addiu\s+\$sp,\s*-", d))
        is_prologue += prologue
        calls, jumps, other, _ = ref_breakdown(ea)
        if calls > 0:
            kind = "jal_target"; jal += 1
        elif jumps > 0:
            kind = "jump/tailcall"; jonly += 1
        else:
            kind = "no_direct_ref"; noref += 1
        cont = ida_funcs.get_func(ea).start_ea
        by_container.setdefault(cont, []).append(ea)
        t1_rows.append({"address": f"0x{ea:08X}", "container": f"0x{cont:08X}",
                        "prologue": "yes" if prologue else "no", "calls": calls,
                        "jumps": jumps, "kind": kind, "disasm": d})

    split_containers = {c: v for c, v in by_container.items() if v}
    print(f"mid-function reverse-gap entries : {len(mid)}")
    print(f"  with a valid stack prologue    : {is_prologue}/{len(mid)}")
    print(f"  reached by a call (jal)        : {jal}   <- IDA arguably should have split these")
    print(f"  reached only by jump/tail-call : {jonly}  <- psxrecomp splits, IDA merges (both valid)")
    print(f"  no direct ref (indirect/ptr)   : {noref}")
    print(f"IDA functions that psxrecomp splits further : {len(split_containers)}")
    top = sorted(split_containers.items(), key=lambda kv: -len(kv[1]))[:8]
    print("  most-split IDA functions (extra entry points inside one IDA func):")
    for c, v in top:
        print(f"    {ida_name.get_name(c)} @ 0x{c:08X}: +{len(v)} psxrecomp entries")

    # ---------- TASK 2: data false-positives ----------
    print("\n=============== TASK 2: data false-positives ===============")
    print(f"addresses psxrecomp emitted as func but IDA sees as data: {len(data_fp)}")
    t2_rows = []
    for ea in data_fp:
        calls, jumps, other, callers = ref_breakdown(ea)
        # who references it, and how (jump-table landing = data referenced by jr/lw)
        srcs = ", ".join(f"0x{frm:08X}({k})" for frm, k in callers[:4]) or "(no code xrefs)"
        name = ida_name.get_name(ea) or ""
        t2_rows.append({"address": f"0x{ea:08X}", "name": name, "disasm": dis(ea),
                        "refs": srcs})
        print(f"  0x{ea:08X} {name:16} {dis(ea)[:42]:42}  refs: {srcs}")

    # ---------- TASK 3: decompile recovered functions ----------
    print("\n=============== TASK 3: decompile recovered functions ===============")
    recovered = []
    for ea in data_fp + orphan:
        if not ida_bytes.is_code(ida_bytes.get_flags(ea)):
            ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, 4)
            idc.create_insn(ea)
        if ida_funcs.add_func(ea):
            recovered.append(ea)
    if recovered:
        ida_auto.auto_wait()

    decomp_dir = os.path.join(out_dir, "recovered")
    os.makedirs(decomp_dir, exist_ok=True)
    combined = os.path.join(decomp_dir, "_recovered.c")
    with open(combined, "w", encoding="utf-8") as ref:
        for ea in recovered:
            name = ida_name.get_name(ea)
            try:
                code = str(ida_hexrays.decompile(ida_funcs.get_func(ea)))
            except Exception as e:
                code = f"/* decompile failed: {e} */"
            hdr = f"/* ==== {name} @ 0x{ea:08X} (IDA had missed this) ==== */\n"
            ref.write(hdr + code + "\n\n")
            with open(os.path.join(decomp_dir, f"{name}.c"), "w", encoding="utf-8") as one:
                one.write(hdr + code + "\n")
            print(f"  decompiled {name} @ 0x{ea:08X} ({code.count(chr(10))} lines)")
    print(f"  recovered+decompiled: {len(recovered)} -> {decomp_dir}")

    # write CSVs
    with open(os.path.join(out_dir, "task1_boundaries.csv"), "w", newline="", encoding="utf-8") as fp:
        csv.DictWriter(fp, fieldnames=["address","container","prologue","calls","jumps","kind","disasm"]).writeheader()
        csv.DictWriter(fp, fieldnames=["address","container","prologue","calls","jumps","kind","disasm"]).writerows(t1_rows)
    with open(os.path.join(out_dir, "task2_data_fp.csv"), "w", newline="", encoding="utf-8") as fp:
        w = csv.DictWriter(fp, fieldnames=["address","name","disasm","refs"]); w.writeheader(); w.writerows(t2_rows)
    print(f"\nCSVs: task1_boundaries.csv, task2_data_fp.csv in {out_dir}")

    idapro.close_database(save=False)


if __name__ == "__main__":
    main()
