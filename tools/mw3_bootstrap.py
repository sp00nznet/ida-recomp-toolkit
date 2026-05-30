#!/usr/bin/env python3
"""
Bootstrap a recomp function list for a fresh x86 PE using IDA (no existing recomp).

  py -3.11 tools/mw3_bootstrap.py <exe> <out_config_dir> <out_analysis_dir>

Emits, IDA's independent discovery (which DOES follow vtables, unlike call-graph
discovery):
  <config>/functions.json   - all IDA functions {address,address_int,name,num_instructions}
  <config>/ida_names.txt     - FLIRT-identified library names
  <analysis>/pe_analysis.json - sections / entry / base
  <analysis>/vtables.json     - vtables + virtual-method targets (incl. coverage)
"""
import sys, os, json
import idapro
import ida_auto, ida_funcs, ida_name, ida_segment, ida_bytes, ida_nalt, ida_entry, idautils, ida_ida

GENERIC = ("sub_", "nullsub_", "loc_", "j_", "unknown", "def_", "byte_", "dword_")


def main():
    exe, cfg, ana = sys.argv[1:4]
    os.makedirs(cfg, exist_ok=True); os.makedirs(ana, exist_ok=True)
    if idapro.open_database(exe, run_auto_analysis=True):
        raise SystemExit("open failed")
    ida_auto.auto_wait()
    for sig in ("vc32rtf", "vc32mfc", "vc32mfce", "omvc60", "vcseh", "vcextra"):
        ida_funcs.plan_to_apply_idasgn(sig)
    ida_auto.auto_wait()

    # functions.json
    funcs = []
    for ea in idautils.Functions():
        f = ida_funcs.get_func(ea)
        funcs.append({"address": f"0x{ea:08X}", "address_int": ea,
                      "name": ida_name.get_name(ea),
                      "num_instructions": sum(1 for _ in idautils.Heads(f.start_ea, f.end_ea))})
    json.dump(funcs, open(os.path.join(cfg, "functions.json"), "w"), indent=1)

    named = [(ea, ida_name.get_name(ea)) for ea in idautils.Functions()
             if not ida_name.get_name(ea).startswith(GENERIC)]
    with open(os.path.join(cfg, "ida_names.txt"), "w", encoding="utf-8") as f:
        f.write(f"# {len(named)} FLIRT/identified names (VC6/MFC42/std)\n")
        for ea, n in named:
            f.write(f"0x{ea:08X} {n}\n")

    # pe_analysis.json
    segs = []
    for i in range(ida_segment.get_segm_qty()):
        s = ida_segment.getnseg(i)
        segs.append({"name": ida_segment.get_segm_name(s), "start": f"0x{s.start_ea:X}",
                     "end": f"0x{s.end_ea:X}", "class": ida_segment.get_segm_class(s)})
    pe = {"input": ida_nalt.get_root_filename(),
          "image_base": f"0x{ida_ida.inf_get_min_ea() & 0xFFF00000:X}",
          "entry": f"0x{ida_entry.get_entry(ida_entry.get_entry_ordinal(0)):X}",
          "functions": len(funcs), "named": len(named), "segments": segs}
    json.dump(pe, open(os.path.join(ana, "pe_analysis.json"), "w"), indent=1)

    # vtable scan
    func_start = lambda d: (lambda f: bool(f) and f.start_ea == d)(ida_funcs.get_func(d))
    fset = {f["address_int"] for f in funcs}
    vtables, targets = [], set()
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
            if len(run) >= 3:
                vtables.append({"address": f"0x{ea:08X}", "count": len(run),
                                "entries": [f"0x{t:08X}" for t in run]})
                targets.update(run); ea = p
            else:
                ea += 4
    in_funcs = sum(1 for t in targets if t in fset)
    json.dump({"vtables": len(vtables), "virtual_methods": len(targets),
               "covered_by_functions_json": in_funcs, "tables": vtables},
              open(os.path.join(ana, "vtables.json"), "w"), indent=1)

    print(f"functions.json     : {len(funcs)} functions ({len(named)} named)")
    print(f"vtables            : {len(vtables)} ({len(targets)} virtual methods, "
          f"{in_funcs} covered by functions.json)")
    print(f"wrote: {cfg}\\functions.json, ida_names.txt ; {ana}\\pe_analysis.json, vtables.json")
    idapro.close_database(save=False)


if __name__ == "__main__":
    main()
