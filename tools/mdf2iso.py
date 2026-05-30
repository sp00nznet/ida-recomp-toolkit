#!/usr/bin/env python3
"""Detect an MDF's raw sector layout (via the ISO9660 CD001 descriptor) and
convert it to a plain 2048-byte/sector ISO. Usage: mdf2iso.py <in.mdf> <out.iso>"""
import sys

src, dst = sys.argv[1], sys.argv[2]
# (sector_size, data_offset) candidates: 2048 plain, 2352 Mode1, 2352 Mode2/F1,
# 2336 Mode2 raw, 2448 (2352+96 subchannel) Mode1/Mode2
CANDS = [(2048, 0), (2352, 16), (2352, 24), (2336, 8), (2448, 16), (2448, 24)]

with open(src, "rb") as f:
    head = f.read(64 * 2448)  # enough to cover sector 16 in any layout

chosen = None
for size, off in CANDS:
    pos = 16 * size + off + 1     # "CD001" sits at data byte 1 of logical sector 16
    if head[pos:pos + 5] == b"CD001":
        chosen = (size, off); break

if not chosen:
    sys.exit(f"could not detect sector layout (no CD001 found). first16={head[:16].hex()}")

size, off = chosen
print(f"detected sector_size={size} data_offset={off}")
import os
total = os.path.getsize(src)
nsec = total // size
print(f"sectors={nsec}  -> writing 2048-byte/sector ISO")
with open(src, "rb") as fi, open(dst, "wb") as fo:
    for i in range(nsec):
        fi.seek(i * size + off)
        fo.write(fi.read(2048))
print(f"done: {dst} ({nsec*2048:,} bytes)")
