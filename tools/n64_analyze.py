# Runs INSIDE idat.exe (no idapro import). N64 (extremeg) cross-validation.
#
# Pipeline:
#   1. ROM is already binary-loaded at correct vram (via idat -Tbinary -pmipsb -b).
#   2. Parse symbols.toml -> sections + 763 function boundaries; parse recomp.toml stubs.
#   3. Create CODE segments; seed every known function (exact boundary) + name it.
#   4. auto_wait, then let IDA find ADDITIONAL functions (symbols.toml gaps).
#   5. Boundary agreement check; missed-function detection over the code section.
#   6. Decompile high-value functions + a few stubbed ones to aligned pseudocode.
import os, re
import ida_auto, ida_funcs, ida_bytes, ida_name, ida_segment, ida_hexrays
import ida_lines, idc, idautils, ida_pro, ida_ida

_A = idc.ARGV[1:] if len(idc.ARGV) > 1 else []
PROJ   = _A[0] if len(_A) > 0 else r"$RECOMP_ROOT/n64\extremeg"
OUT    = _A[1] if len(_A) > 1 else r"$IDA_WORK/extremeg"
SYMS   = _A[2] if len(_A) > 2 else os.path.join(PROJ, "symbols.toml")
# find recomp config: <name>.recomp.toml or recomp.toml
RECOMP = _A[3] if len(_A) > 3 else next(
    (os.path.join(PROJ, f) for f in os.listdir(PROJ)
     if f.endswith(".recomp.toml") or f == "recomp.toml"), os.path.join(PROJ, "recomp.toml"))
TAG = os.path.basename(OUT.rstrip("\\/")) or "n64"
os.makedirs(os.path.join(OUT, "decomp"), exist_ok=True)
log = []
def out(s=""): log.append(str(s))


def parse_symbols(path):
    sections, funcs, cur, mode = [], [], {}, None
    def flush():
        if mode == "section" and cur: sections.append(dict(cur))
        elif mode == "func" and cur: funcs.append(dict(cur))
    with open(path, encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if s == "[[section]]":
                flush(); mode, cur = "section", {}
            elif s == "[[section.functions]]":
                flush(); mode, cur = "func", {}
            elif "=" in s:
                k, v = (x.strip() for x in s.split("=", 1))
                if k == "name": cur["name"] = v.strip('"')
                elif k in ("rom", "vram", "size"): cur[k] = int(v, 16)
    flush()
    return sections, funcs


def parse_stubs(path):
    with open(path, encoding="utf-8") as f:
        txt = f.read()
    m = re.search(r"stubs\s*=\s*\[(.*?)\]", txt, re.S)
    return set(re.findall(r'"([^"]+)"', m.group(1))) if m else set()


def main():
    ida_auto.auto_wait()
    sections, funcs = parse_symbols(SYMS)
    stubs = parse_stubs(RECOMP)
    out(f"symbols.toml: {len(sections)} sections, {len(funcs)} functions; "
        f"recomp stubs: {len(stubs)}")

    # 1. create CODE segments for each section
    for sec in sections:
        start, end = sec["vram"], sec["vram"] + sec["size"]
        seg = ida_segment.segment_t(); seg.start_ea, seg.end_ea = start, end
        seg.bitness = 2  # 64-bit: N64 R4300 -> Hex-Rays uses the MIPS64 decompiler
        ida_segment.add_segm_ex(seg, sec["name"], "CODE", ida_segment.ADDSEG_QUIET)

    # 2. seed every known function with its EXACT boundary + name
    by_vram = {}
    for fn in funcs:
        ea, size, name = fn["vram"], fn.get("size", 0), fn["name"]
        by_vram[ea] = fn
        ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, max(size, 4))
        idc.create_insn(ea)
        if size:
            ida_funcs.add_func(ea, ea + size)
        else:
            ida_funcs.add_func(ea)
        ida_name.set_name(ea, name, ida_name.SN_NOCHECK | ida_name.SN_FORCE)
    ida_auto.auto_wait()
    seeded = sum(1 for fn in funcs if ida_funcs.get_func(fn["vram"]))
    out(f"seeded functions IDA accepted: {seeded}/{len(funcs)}")

    # 3. let IDA find ADDITIONAL functions inside the code section (symbols.toml gaps)
    rom_secs = [s for s in sections if "rom" in s and "vram" in s and "size" in s]
    code = next((s for s in sections if s.get("name") == "code"),
                max(rom_secs, key=lambda s: s["size"]))
    c0, c1 = code["vram"], code["vram"] + code["size"]
    known = sorted(by_vram)
    # walk gaps between consecutive known functions; flag prologues IDA/we see
    missed = []
    for i, ea in enumerate(known):
        if not (c0 <= ea < c1):
            continue
        end = ea + by_vram[ea].get("size", 0)
        nxt = known[i + 1] if i + 1 < len(known) else c1
        g = end  # gap start
        while g + 4 <= nxt:
            if not ida_bytes.is_mapped(g):
                break
            w = ida_bytes.get_dword(g)
            line = ida_lines.tag_remove(idc.generate_disasm_line(g, 0) or "")
            # MIPS prologue 'addiu $sp, -N' encodes as 0x27BD....  with high bit set
            if (w & 0xFFFF0000) == 0x27BD0000 and (w & 0x8000):
                missed.append((g, line))
                f2 = ida_funcs.get_func(g)
                if not f2:
                    idc.create_insn(g); ida_funcs.add_func(g)
                break
            g += 4
    ida_auto.auto_wait()
    out(f"likely MISSED functions (prologue in gap, not in symbols.toml): {len(missed)}")
    for g, line in missed[:25]:
        out(f"   0x{g:08X}  {line}")

    # 4. the real cross-validation: functions IDA created in the code section that
    #    are NOT in symbols.toml (i.e. functions N64Recomp's table may have missed).
    code_vrams = {fn["vram"] for fn in funcs if c0 <= fn["vram"] < c1}
    ida_code = [ea for ea in idautils.Functions() if c0 <= ea < c1]
    extra = sorted(set(ida_code) - code_vrams)
    out(f"code-section functions: symbols.toml={len(code_vrams)}  IDA={len(ida_code)}  "
        f"IDA-only(recomp may have missed)={len(extra)}")
    for ea in extra[:25]:
        line = ida_lines.tag_remove(idc.generate_disasm_line(ea, 0) or "")
        out(f"   0x{ea:08X}  {line}")
    # contiguity is informational only (trailing padding between funcs is normal)
    contig = gap = 0
    ks = sorted(code_vrams)
    for i, ea in enumerate(ks):
        end = ea + by_vram[ea].get("size", 0)
        nxt = ks[i + 1] if i + 1 < len(ks) else c1
        if end == nxt: contig += 1
        elif end < nxt: gap += 1
    out(f"boundary layout: {contig} contiguous, {gap} with trailing padding (both normal)")

    # 5. decompile high-value functions + a few stubs, to aligned pseudocode
    decomp_targets = sorted((fn for fn in funcs if fn["name"] not in stubs and c0 <= fn["vram"] < c1),
                            key=lambda f: -f.get("size", 0))[:15]
    stub_targets = [fn for fn in funcs if fn["name"] in stubs][:5]
    ok = 0
    if ida_hexrays.init_hexrays_plugin():
        with open(os.path.join(OUT, "decomp", f"_{TAG}_reference.c"), "w", encoding="utf-8") as ref:
            for fn in decomp_targets + stub_targets:
                ea = fn["vram"]; name = fn["name"]
                tag = "STUB" if name in stubs else "func"
                try:
                    code_s = str(ida_hexrays.decompile(ida_funcs.get_func(ea))); ok += 1
                except Exception as e:
                    code_s = f"/* decompile failed: {e} */"
                hdr = f"/* ==== [{tag}] {name} @ 0x{ea:08X} size=0x{fn.get('size',0):X} ==== */\n"
                ref.write(hdr + code_s + "\n\n")
        out(f"decompiled {ok}/{len(decomp_targets)+len(stub_targets)} -> decomp/_{TAG}_reference.c")
    else:
        out("Hex-Rays MIPS decompiler unavailable")

    out(f"\nIDA total functions now: {sum(1 for _ in idautils.Functions())}")
    with open(os.path.join(OUT, f"{TAG}_summary.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(log))
    ida_pro.qexit(0)

main()
