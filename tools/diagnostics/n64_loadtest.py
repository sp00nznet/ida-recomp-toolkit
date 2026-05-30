#!/usr/bin/env python3
"""Verify a controlled binary load of an N64 ROM at the recomp's vram."""
import sys
import idapro

rom = sys.argv[1]
args = sys.argv[2] if len(sys.argv) > 2 else ""
idapro.enable_console_messages(True)
print(f"[*] open with args: {args!r}", file=sys.stderr)
try:
    rc = idapro.open_database(rom, True, args if args else None)
    print(f"[*] open_database rc={rc}", file=sys.stderr)
except Exception as e:
    print(f"[!] exception: {e}", file=sys.stderr)
    raise

import ida_auto, ida_segment, ida_bytes, idc, ida_lines, ida_ida
ida_auto.auto_wait()

print(f"min_ea=0x{ida_ida.inf_get_min_ea():X}  max_ea=0x{ida_ida.inf_get_max_ea():X}")
print(f"procname={ida_ida.inf_get_procname()}")
print("segments:")
for i in range(ida_segment.get_segm_qty()):
    s = ida_segment.getnseg(i)
    print(f"  {ida_segment.get_segm_name(s):12} 0x{s.start_ea:X}-0x{s.end_ea:X}")

for ea in (0x8004B8A0, 0x8004D128, 0x80000000):
    mapped = ida_bytes.is_mapped(ea)
    line = ida_lines.tag_remove(idc.generate_disasm_line(ea, 0) or "") if mapped else "(unmapped)"
    raw = " ".join(f"{ida_bytes.get_byte(ea+i):02X}" for i in range(4)) if mapped else ""
    print(f"  0x{ea:08X} mapped={mapped} bytes=[{raw}]  {line}")

idapro.close_database(save=False)
