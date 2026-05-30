#!/usr/bin/env python3
"""
Emit the missed vtable virtual methods as a functions.json-schema patch.

  py -3.11 tools/crimson_emit_patch.py <decrypted.exe> <config_dir> <out_dir>

Writes:
  <out_dir>/missed_virtuals.functions.json   -- the N missed entries (ready to merge)
  <out_dir>/functions.merged.json            -- original functions.json + the patch
Schema matches functions.json: {address, address_int, name, num_instructions}.
"""
import sys, os, json
import idapro

import ida_auto, ida_bytes, ida_funcs, ida_segment, ida_name, idautils

MIN_RUN = 3


def main():
    exe, cfg_dir, out_dir = sys.argv[1:4]
    os.makedirs(out_dir, exist_ok=True)
    if idapro.open_database(exe, run_auto_analysis=True):
        raise SystemExit("open failed")
    ida_auto.auto_wait()

    orig = json.load(open(os.path.join(cfg_dir, "functions.json"), encoding="utf-8"))
    recomp = {r.get("address_int") or int(r["address"], 16) for r in orig}

    func_start = lambda d: (lambda f: bool(f) and f.start_ea == d)(ida_funcs.get_func(d))
    targets = set()
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
                targets.update(run); ea = p
            else:
                ea += 4

    missed = sorted(t for t in targets if t not in recomp)

    def num_insns(ea):
        f = ida_funcs.get_func(ea)
        return sum(1 for _ in idautils.Heads(f.start_ea, f.end_ea)) if f else 0

    def entry(ea):
        n = ida_name.get_name(ea)
        if not n or n.startswith("sub_"):
            n = f"sub_{ea:08X}"        # match functions.json naming convention
        return {"address": f"0x{ea:08X}", "address_int": ea,
                "name": n, "num_instructions": num_insns(ea),
                "source": "ida_vtable_scan"}

    patch = [entry(ea) for ea in missed]
    json.dump(patch, open(os.path.join(out_dir, "missed_virtuals.functions.json"), "w"), indent=1)

    # pre-merged full list (dedup by address_int, original wins)
    seen = set(recomp)
    merged = list(orig)
    for e in patch:
        if e["address_int"] not in seen:
            merged.append(e); seen.add(e["address_int"])
    merged.sort(key=lambda r: r.get("address_int") or int(r["address"], 16))
    json.dump(merged, open(os.path.join(out_dir, "functions.merged.json"), "w"), indent=1)

    print(f"missed virtuals emitted : {len(patch)}")
    print(f"original functions.json : {len(orig)}")
    print(f"merged functions.json   : {len(merged)}  (+{len(merged)-len(orig)})")
    print(f"wrote: missed_virtuals.functions.json , functions.merged.json -> {out_dir}")
    idapro.close_database(save=False)


if __name__ == "__main__":
    main()
