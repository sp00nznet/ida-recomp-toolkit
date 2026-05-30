# idat diagnostic: why does Hex-Rays return None for N64 funcs?
import os
import ida_auto, ida_funcs, ida_bytes, ida_name, ida_segment, ida_hexrays, idc, ida_pro

PROJ=r"D:\recomp\n64\extremeg"; OUT=r"E:\ida\work\extremeg"
def parse_symbols(path):
    sections,funcs,cur,mode=[],[],{},None
    def flush():
        if mode=="section" and cur: sections.append(dict(cur))
        elif mode=="func" and cur: funcs.append(dict(cur))
    for line in open(path,encoding="utf-8"):
        s=line.strip()
        if s=="[[section]]": flush(); mode,cur="section",{}
        elif s=="[[section.functions]]": flush(); mode,cur="func",{}
        elif "=" in s:
            k,v=(x.strip() for x in s.split("=",1))
            if k=="name": cur["name"]=v.strip('"')
            elif k in ("rom","vram","size"): cur[k]=int(v,16)
    flush(); return sections,funcs

ida_auto.auto_wait()
sections,funcs=parse_symbols(os.path.join(PROJ,"symbols.toml"))
for sec in sections:
    seg=ida_segment.segment_t(); seg.start_ea=sec["vram"]; seg.end_ea=sec["vram"]+sec["size"]; seg.bitness=1
    ida_segment.add_segm_ex(seg, sec["name"], "CODE", ida_segment.ADDSEG_QUIET)
for fn in funcs:
    ea,size=fn["vram"],fn.get("size",0)
    ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, max(size,4)); idc.create_insn(ea)
    ida_funcs.add_func(ea, ea+size) if size else ida_funcs.add_func(ea)
ida_auto.auto_wait()

log=[]
log.append(f"init_hexrays_plugin: {ida_hexrays.init_hexrays_plugin()}")
log.append(f"hexrays version: {ida_hexrays.get_hexrays_version()}")
for nm,ea in (("func_8004D128",0x8004D128),("func_8004F954",0x8004F954),("func_800546B0",0x800546B0)):
    f=ida_funcs.get_func(ea)
    hf=ida_hexrays.hexrays_failure_t()
    try:
        cf=ida_hexrays.decompile(f, hf)
        if cf is None:
            log.append(f"{nm}: None  err@0x{hf.errea:X} code={hf.code} desc={hf.desc()!r}")
        else:
            txt=str(cf)
            log.append(f"{nm}: OK {len(txt.splitlines())} lines; head={txt.splitlines()[1] if len(txt.splitlines())>1 else txt[:60]!r}")
    except Exception as e:
        log.append(f"{nm}: EXC {e}")
open(os.path.join(OUT,"decomp_diag.txt"),"w",encoding="utf-8").write("\n".join(log))
ida_pro.qexit(0)
