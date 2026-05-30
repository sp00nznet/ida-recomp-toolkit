#!/usr/bin/env python3
"""
Headless IDA Pro analysis via idalib. No GUI required.

Run with Python 3.11 (the interpreter idalib is installed into):
    py -3.11 tools/analyze.py <binary> [command] [arg]

Commands:
    info                      Counts + entry points (default)
    funcs [substr]            List functions (optionally filter by name substring)
    imports                   List imported symbols
    strings [min_len]         List strings (default min length 5)
    decompile <name|0xADDR>   Decompile one function to pseudocode
    disasm <name|0xADDR>      Disassemble one function

This is a starting template -- extend it with any IDAPython API you need
(ida_funcs, idautils, ida_bytes, ida_hexrays, ida_xref, ...).
"""
import sys
import idapro  # MUST be imported before any ida_* module

import ida_auto, ida_funcs, ida_name, ida_entry, ida_hexrays
import ida_bytes, ida_nalt, ida_lines, idautils, idc


def resolve_ea(target: str) -> int:
    """Accept a function name or a 0x-prefixed address."""
    if target.lower().startswith("0x"):
        return int(target, 16)
    ea = ida_name.get_name_ea(idc.BADADDR, target)
    if ea == idc.BADADDR:
        raise SystemExit(f"No symbol named {target!r}")
    return ea


def cmd_info():
    funcs = list(idautils.Functions())
    print(f"file        : {ida_nalt.get_root_filename()}")
    print(f"functions   : {len(funcs)}")
    print(f"entry points: {ida_entry.get_entry_qty()}")
    for i in range(ida_entry.get_entry_qty()):
        o = ida_entry.get_entry_ordinal(i)
        ea = ida_entry.get_entry(o)
        print(f"  {hex(ea)}  {ida_name.get_name(ea)}")


def cmd_funcs(substr=None):
    for ea in idautils.Functions():
        name = ida_funcs.get_func_name(ea)
        if substr and substr.lower() not in name.lower():
            continue
        print(f"{hex(ea)}  {name}")


def cmd_imports():
    n = ida_nalt.get_import_module_qty()
    for i in range(n):
        mod = ida_nalt.get_import_module_name(i) or "?"
        def cb(ea, name, ordinal):
            print(f"{mod:20} {name or ('ord#'+str(ordinal))}")
            return True
        ida_nalt.enum_import_names(i, cb)


def cmd_strings(min_len=5):
    min_len = int(min_len)
    for s in idautils.Strings():
        if s.length >= min_len:
            print(f"{hex(s.ea)}  {str(s)!r}")


def cmd_decompile(target):
    if not ida_hexrays.init_hexrays_plugin():
        raise SystemExit("Hex-Rays decompiler not available")
    ea = resolve_ea(target)
    f = ida_funcs.get_func(ea)
    if not f:
        raise SystemExit(f"No function at {hex(ea)}")
    print(str(ida_hexrays.decompile(f)))


def cmd_disasm(target):
    ea = resolve_ea(target)
    f = ida_funcs.get_func(ea)
    if not f:
        raise SystemExit(f"No function at {hex(ea)}")
    for head in idautils.Heads(f.start_ea, f.end_ea):
        print(f"{hex(head)}  {ida_lines.tag_remove(idc.generate_disasm_line(head, 0))}")


COMMANDS = {
    "info": cmd_info, "funcs": cmd_funcs, "imports": cmd_imports,
    "strings": cmd_strings, "decompile": cmd_decompile, "disasm": cmd_disasm,
}


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    binary = sys.argv[1]
    cmd = sys.argv[2] if len(sys.argv) > 2 else "info"
    args = sys.argv[3:]
    if cmd not in COMMANDS:
        raise SystemExit(f"Unknown command {cmd!r}. Choose from: {', '.join(COMMANDS)}")

    print(f"[*] Opening {binary} (headless)...", file=sys.stderr)
    if idapro.open_database(binary, run_auto_analysis=True):
        raise SystemExit("Failed to open/analyze database")
    ida_auto.auto_wait()
    try:
        COMMANDS[cmd](*args)
    finally:
        idapro.close_database(save=False)


if __name__ == "__main__":
    main()
