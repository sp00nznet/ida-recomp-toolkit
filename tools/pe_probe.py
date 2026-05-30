#!/usr/bin/env python3
"""Quick PE health/identity probe: segments, compiler, SafeDisc markers, a decompile."""
import sys
import idapro
import ida_auto, ida_segment, ida_funcs, ida_hexrays, ida_nalt, idautils, ida_name, idc

if idapro.open_database(sys.argv[1], run_auto_analysis=True):
    raise SystemExit("open failed")
ida_auto.auto_wait()

print("segments:")
safedisc = False
for i in range(ida_segment.get_segm_qty()):
    s = ida_segment.getnseg(i)
    nm = ida_segment.get_segm_name(s)
    if any(k in nm.lower() for k in ("stxt", "icd", "data774", "txt2")):
        safedisc = True
    print(f"  {nm:12} 0x{s.start_ea:X}-0x{s.end_ea:X} class={ida_segment.get_segm_class(s)}")
print(f"SafeDisc markers: {safedisc}")
print(f"functions: {sum(1 for _ in idautils.Functions())}")

# named (FLIRT) sample -> proves it's real, identifiable code
named = [(ea, ida_name.get_name(ea)) for ea in idautils.Functions()
         if not ida_name.get_name(ea).startswith(("sub_", "nullsub_", "loc_", "j_", "unknown"))]
print(f"named functions: {len(named)} ; sample:")
for ea, n in named[:12]:
    print(f"   0x{ea:08X} {n}")

# decompile a mid function to confirm real code
print(f"Hex-Rays: {ida_hexrays.init_hexrays_plugin()}")
fns = list(idautils.Functions())
if fns:
    ea = fns[len(fns)//2]
    try:
        print(f"--- decompile 0x{ea:08X} (head) ---")
        print("\n".join(str(ida_hexrays.decompile(ida_funcs.get_func(ea))).splitlines()[:10]))
    except Exception as e:
        print(f"decompile failed: {e}")
idapro.close_database(save=False)
