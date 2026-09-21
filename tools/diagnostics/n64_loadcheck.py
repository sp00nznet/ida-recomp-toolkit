# Runs INSIDE idat.exe (do NOT import idapro). Verifies binary-load alignment.
import ida_auto, ida_segment, ida_bytes, idc, ida_lines, ida_ida, ida_pro

ida_auto.auto_wait()
out = []
out.append(f"min_ea=0x{ida_ida.inf_get_min_ea():X}  max_ea=0x{ida_ida.inf_get_max_ea():X}")
out.append(f"procname={ida_ida.inf_get_procname()}  is_be={ida_ida.inf_is_be()}")
out.append("segments:")
for i in range(ida_segment.get_segm_qty()):
    s = ida_segment.getnseg(i)
    out.append(f"  {ida_segment.get_segm_name(s):12} 0x{s.start_ea:X}-0x{s.end_ea:X}")
for ea in (0x8004B8A0, 0x8004D128, 0x80000000):
    m = ida_bytes.is_mapped(ea)
    raw = " ".join(f"{ida_bytes.get_byte(ea+i):02X}" for i in range(4)) if m else ""
    line = ida_lines.tag_remove(idc.generate_disasm_line(ea, 0) or "") if m else "(unmapped)"
    out.append(f"  0x{ea:08X} mapped={m} [{raw}]  {line}")

with open(r"$IDA_WORK/extremeg\loadcheck.txt", "w", encoding="utf-8") as f:
    f.write("\n".join(out))
ida_pro.qexit(0)
