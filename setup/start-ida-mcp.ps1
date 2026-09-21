<#
.SYNOPSIS
  Start the headless IDA Pro MCP server (idalib-mcp) on a target binary.

.DESCRIPTION
  Opens <binary> with IDA's idalib (no GUI), runs auto-analysis, and serves
  the ida-pro-mcp tools over SSE at http://127.0.0.1:<port>/sse so Claude Code
  (via the "ida-headless" entry in .mcp.json) can drive it.

  The binary is fixed for the life of the server. To analyze a different
  binary, stop this server (Ctrl+C, or -Stop) and start it again.

.EXAMPLE
  .\start-ida-mcp.ps1 C:\path\to\sample.exe
  .\start-ida-mcp.ps1 C:\path\to\sample.exe -Port 8745
  .\start-ida-mcp.ps1 -Stop          # kill whatever is serving on the port
#>
param(
  [Parameter(Position = 0)]
  [string]$Binary,
  [int]$Port = 8745,
  [switch]$Stop
)

$ErrorActionPreference = "Stop"
$exe = "$env:LOCALAPPDATA\Programs\Python\Python311\Scripts\idalib-mcp.exe"

function Stop-OnPort([int]$p) {
  $conns = Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue
  foreach ($c in $conns) {
    Write-Host "Stopping PID $($c.OwningProcess) on port $p..."
    Stop-Process -Id $c.OwningProcess -Force -ErrorAction SilentlyContinue
  }
}

if ($Stop) { Stop-OnPort $Port; Write-Host "Done."; return }

if (-not $Binary) { throw "Usage: .\start-ida-mcp.ps1 <binary> [-Port N]   (or -Stop)" }
if (-not (Test-Path $Binary)) { throw "Binary not found: $Binary" }
if (-not (Test-Path $exe))    { throw "idalib-mcp not found at $exe" }

# Free the port if something is already there.
Stop-OnPort $Port

Write-Host "Starting headless IDA MCP server on $Binary (port $Port)..."
# Runs in the foreground; press Ctrl+C to stop. Analysis of large binaries can take a while.
& $exe --host 127.0.0.1 --port $Port $Binary
