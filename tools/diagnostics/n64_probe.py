# idat probe: verify boundary check + list unseeded functions.
import os, re
import ida_auto, ida_funcs, ida_bytes, ida_name, ida_segment, ida_lines, idc, ida_pro

PROJ = r"D:\recomp\n64\extremeg"; OUT = r"E:\ida\work\extremeg"
def parse_symbols(path):
    sections, funcs, cur, mode = [], [], {}, None
    def flush():
        if mode=="section" and cur: sections.append(dict(cur))
        elif mode=="func" and cur: funcs.append(dict(cur))
    for line in open(path, encoding="utf-8"):
        s=line.strip()
        if s=="[[section]]": flush(); mode,cur="section",{}
        elif s=="[[section.functions]]": flush(); mode,cur="func",{}
        elif "=" in s:
            k,v=(x.strip() for x in s.split("=",1))
            if k=="name": cur["name"]=v.strip('"')
            elif k in ("rom","vram","size"): cur[k]=int(v,16)
    flush(); return sections, funcs

ida_auto.auto_wait()
sections, funcs = parse_symbols(os.path.join(PROJ,"symbols.toml"))
code = next(s for s in sections if s["name"]=="code")
c0,c1 = code["vram"], code["vram"]+code["size"]
by_vram = {f["vram"]: f for f in funcs}

# seed
for fn in funcs:
    ea,size=fn["vram"],fn.get("size",0)
    ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, max(size,4)); idc.create_insn(ea)
    ida_funcs.add_func(ea, ea+size) if size else ida_funcs.add_func(ea)
    ida_name.set_name(ea, fn["name"], ida_name.SN_NOCHECK|ida_name.SN_FORCE)
ida_auto.auto_wait()

log=[]
unseeded=[f for f in funcs if not ida_funcs.get_func(f["vram"])]
log.append(f"UNSEEDED ({len(unseeded)}):")
for f in unseeded:
    ea=f["vram"]
    cf=ida_funcs.get_func(ea)
    log.append(f"  {f['name']} @ 0x{ea:08X} size=0x{f.get('size',0):X} "
               f"-> inside {ida_name.get_name(cf.start_ea) if cf else 'none'}")

# verify boundary 'smell' on 3 flagged funcs: show insns near declared end
def insns_around(ea_end, name, size):
    log.append(f"\n{name} declared end=0x{ea_end:08X} (size 0x{size:X}):")
    # show last few heads before end and what's at end
    ea = ea_end - 16
    for _ in range(8):
        if ea>=ea_end+8: break
        head = ida_bytes.is_head(ida_bytes.get_flags(ea))
        mark = " <== declared end" if ea==ea_end else ""
        line = ida_lines.tag_remove(idc.generate_disasm_line(ea,0) or "")
        log.append(f"   0x{ea:08X} head={int(head)} {line}{mark}")
        ea = idc.next_head(ea, ea_end+32) if head else ea+4
        if ea==idc.BADADDR: break

for nm in ("func_800546B0","func_80055854","func_8005DC74"):
    f=next((x for x in funcs if x["name"]==nm), None)
    if f: insns_around(f["vram"]+f["size"], nm, f["size"])

# is the next seeded function exactly at each declared end?
contig=gap=overlap=0
ks=sorted(k for k in by_vram if c0<=k<c1)
for i,ea in enumerate(ks):
    end=ea+by_vram[ea].get("size",0)
    nxt=ks[i+1] if i+1<len(ks) else c1
    if end==nxt: contig+=1
    elif end<nxt: gap+=1
    else: overlap+=1
log.append(f"\ncontiguous={contig} gap_after={gap} overlap={overlap} (of {len(ks)} code funcs)")

open(os.path.join(OUT,"probe.txt"),"w",encoding="utf-8").write("\n".join(log))
ida_pro.qexit(0)
