# Headless IDA Pro + Claude

IDA Professional 9.1 driven headlessly (no GUI). Two complementary workflows are set up.

- **IDA install:** `C:\Program Files\IDA Professional 9.1`
- **Python:** 3.11 (`%LOCALAPPDATA%\Programs\Python\Python311`) — `idapro` + `ida-pro-mcp` are installed here.
- **License:** verified working with idalib (no GUI launch needed).

---

## Workflow 1 — idalib scripting (script-driven)

Claude writes normal Python that opens a binary, analyzes it headlessly, and prints results.
The key rule: **`import idapro` must be the first import.**

```powershell
py -3.11 tools/analyze.py <binary> info
py -3.11 tools/analyze.py <binary> funcs [substr]
py -3.11 tools/analyze.py <binary> imports
py -3.11 tools/analyze.py <binary> strings [min_len]
py -3.11 tools/analyze.py <binary> decompile <name|0xADDR>
py -3.11 tools/analyze.py <binary> disasm   <name|0xADDR>
```

`tools/analyze.py` is a template — extend it with any IDAPython API (`ida_funcs`,
`idautils`, `ida_bytes`, `ida_hexrays`, `ida_xref`, …). Best for batch jobs,
custom queries, and anything scripted.

> Note: idalib locks the input file's database. Don't run a script on the same
> binary that the MCP server (below) currently has open — use a copy or stop the server.

---

## Workflow 2 — IDA Pro MCP (conversational tools)

`ida-pro-mcp`'s **headless** server (`idalib-mcp`) exposes IDA as MCP tools
(list/decompile functions, xrefs, rename, set comments, read bytes, …) that Claude
calls directly. The binary is fixed when the server starts.

**Start the server on a target:**
```powershell
.\start-ida-mcp.ps1 C:\path\to\sample.exe        # serves http://127.0.0.1:8745/sse
.\start-ida-mcp.ps1 -Stop                        # stop it
```

**Claude Code registration:** `.mcp.json` in this folder registers the server as
`ida-headless` (SSE, `http://127.0.0.1:8745/sse`). To use it:
1. Start the server with the script above (it must be running first).
2. In Claude Code, approve the `ida-headless` MCP server when prompted
   (run `/mcp` to check status; you may need to restart Claude Code so it
   picks up the new `.mcp.json`).
3. Ask Claude to use the IDA tools on the loaded binary.

To analyze a different binary, stop the server and start it on the new file.

---

## Maintenance notes

- A vendored fix was applied to
  `…\Python311\Lib\site-packages\ida_pro_mcp\mcp-plugin.py`: its `TypedDict`
  import was changed to come from `typing_extensions` on Python < 3.12 (pydantic
  requires this). **Re-apply after any `pip install -U ida-pro-mcp`** if it
  starts crashing on startup with a `PydanticUserError` about `TypedDict`.
- idalib was activated via `py-activate-idalib.py`; config lives at
  `%APPDATA%\Hex-Rays\IDA Pro\ida-config.json`.
- The classic batch runner `idat.exe -B` is also available if you ever want
  per-run IDA processes instead of the library.
```
