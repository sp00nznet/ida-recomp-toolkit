# Runs INSIDE idat.exe. N64 OVERLAY game loader + cross-validation.
# Loaded flat (-Tbinary -pmipsb -b0) to get a MIPS64 db; then maps each chosen
# section to its TRUE vram by copying ROM bytes, selecting a non-overlapping set
# (overlays that share vram are mutually exclusive at runtime -> skip + report).
import os, re
import ida_auto, ida_funcs, ida_bytes, ida_name, ida_segment, ida_hexrays
import ida_lines, idc, idautils, ida_pro, ida_nalt

_A = idc.ARGV[1:] if len(idc.ARGV) > 1 else []
PROJ = _A[0]; OUT = _A[1]; SYMS = _A[2]
TAG = os.path.basename(OUT.rstrip("\\/")) or "n64ovl"
os.makedirs(os.path.join(OUT, "decomp"), exist_ok=True)
log = []; out = lambda s="": log.append(str(s))


def parse_symbols(path):
    # Parse per-section blocks so each function is scoped to the section that
    # DECLARES it (critical for overlay games where sections share vram ranges:
    # a vram-range attach would leak overlay funcs into resident sections).
    text = open(path, encoding="utf-8").read()
    sections, all_funcs = [], []
    for chunk in text.split("[[section]]")[1:]:
        chunk = chunk.split("[[")[0]          # stop at the next top-level table
        sec = {}
        for line in chunk.splitlines():
            s = line.strip()
            if s.startswith("{") or s.startswith("functions"):
                break
            if "=" in s:
                k, v = (x.strip() for x in s.split("=", 1))
                if k == "name": sec["name"] = v.strip('"')
                elif k in ("rom", "vram", "size"):
                    try: sec[k] = int(v, 16)
                    except ValueError: pass
        fns = []
        for blk in re.findall(r"\{[^}]*\}", chunk):
            nm = re.search(r'name\s*=\s*"([^"]+)"', blk)
            vr = re.search(r"vram\s*=\s*(0x[0-9A-Fa-f]+)", blk)
            sz = re.search(r"size\s*=\s*(0x[0-9A-Fa-f]+)", blk)
            if nm and vr:
                fns.append({"name": nm.group(1), "vram": int(vr.group(1), 16),
                            "size": int(sz.group(1), 16) if sz else 0})
        sec["funcs"] = fns
        all_funcs.extend(fns)
        sections.append(sec)
    return sections, all_funcs


def main():
    ida_auto.auto_wait()
    rom_path = ida_nalt.get_input_file_path()
    data = open(rom_path, "rb").read()
    sections, funcs = parse_symbols(SYMS)
    rom_secs = [s for s in sections if all(k in s for k in ("rom", "vram", "size")) and s["size"] > 0]
    out(f"{TAG}: {len(sections)} sections ({len(rom_secs)} rom-backed), {len(funcs)} functions")

    # greedy non-overlapping selection (sorted by rom order)
    chosen, skipped, ranges = [], [], []
    for sec in sorted(rom_secs, key=lambda s: s["rom"]):
        a, b = sec["vram"], sec["vram"] + sec["size"]
        if any(a < rb and ra < b for ra, rb in ranges):
            skipped.append(sec)
        else:
            chosen.append(sec); ranges.append((a, b))
    out(f"selected non-overlapping sections: {len(chosen)} ; skipped (overlay conflicts): {len(skipped)}")
    out("  skipped: " + ", ".join(s["name"] for s in skipped))

    # delete the flat ROM segment(s) at low addresses, then map chosen sections at vram
    for i in range(ida_segment.get_segm_qty() - 1, -1, -1):
        s = ida_segment.getnseg(i)
        if s.start_ea < 0x80000000:
            ida_segment.del_segm(s.start_ea, ida_segment.SEGMOD_KILL)
    for sec in chosen:
        a, b = sec["vram"], sec["vram"] + sec["size"]
        seg = ida_segment.segment_t(); seg.start_ea, seg.end_ea = a, b; seg.bitness = 2
        ida_segment.add_segm_ex(seg, sec["name"], "CODE", ida_segment.ADDSEG_QUIET)
        ida_bytes.put_bytes(a, data[sec["rom"]: sec["rom"] + sec["size"]])

    # seed functions in chosen sections
    seed_funcs = [f for sec in chosen for f in sec.get("funcs", [])]
    for f in seed_funcs:
        ea, size = f["vram"], f.get("size", 0)
        ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, max(size, 4)); idc.create_insn(ea)
        ida_funcs.add_func(ea, ea + size) if size else ida_funcs.add_func(ea)
        ida_name.set_name(ea, f["name"], ida_name.SN_NOCHECK | ida_name.SN_FORCE)
    ida_auto.auto_wait()
    seeded = sum(1 for f in seed_funcs if ida_funcs.get_func(f["vram"]))
    out(f"seeded {seeded}/{len(seed_funcs)} functions across selected sections")

    # cross-validate: IDA-only functions inside the selected code ranges
    known = {f["vram"] for f in seed_funcs}
    ida_in = [ea for ea in idautils.Functions() if any(a <= ea < b for a, b in ranges)]
    extra = sorted(set(ida_in) - known)
    out(f"functions in selected ranges: symbols={len(known)} IDA={len(ida_in)} IDA-only={len(extra)}")
    for ea in extra[:20]:
        out(f"   0x{ea:08X}  {ida_lines.tag_remove(idc.generate_disasm_line(ea, 0) or '')}")

    # decompile the largest selected functions
    ok = 0
    if ida_hexrays.init_hexrays_plugin():
        tgts = sorted(seed_funcs, key=lambda f: -f.get("size", 0))[:15]
        with open(os.path.join(OUT, "decomp", f"_{TAG}_reference.c"), "w", encoding="utf-8") as ref:
            for f in tgts:
                ea = f["vram"]
                try:
                    code_s = str(ida_hexrays.decompile(ida_funcs.get_func(ea)))
                    if code_s != "None": ok += 1
                except Exception as e:
                    code_s = f"/* fail: {e} */"
                ref.write(f"/* {f['name']} @ 0x{ea:08X} size=0x{f.get('size',0):X} */\n{code_s}\n\n")
        out(f"decompiled {ok}/{len(tgts)} largest -> decomp/_{TAG}_reference.c")

    out(f"\nIDA total functions: {sum(1 for _ in idautils.Functions())}")
    open(os.path.join(OUT, f"{TAG}_summary.txt"), "w", encoding="utf-8").write("\n".join(log))
    ida_pro.qexit(0)

main()
