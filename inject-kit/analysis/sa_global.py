# -*- coding: utf-8 -*-
"""sa_global.py -- read the small live dumps that were captured exactly at the
highlight globals, to test the hypothesis that RVA 0x72BE6C0 is a *global
pointer variable* (g_pHighlightContextTable) rather than the table itself.

  0x72BE6C0 -> VA 0x7FF69093E6C0  (scdump\72_7FF69093E6C0.bin, 32 bytes)
"""
import glob
import os
import struct

for va, want in ((0x7FF69093E6C0, 0x20),):
    hexv = "%X" % va
    cands = sorted(glob.glob(r"C:\ProgramData\scdump\*_%s.bin" % hexv),
                   key=os.path.getmtime)
    print("files for VA 0x%X: %s" % (va, [os.path.basename(c) for c in cands]))
    if not cands:
        continue
    raw = open(cands[-1], "rb").read()
    print("  size 0x%X" % len(raw))
    for off in range(0, min(len(raw), 0x40), 8):
        q = struct.unpack_from("<Q", raw, off)[0]
        lo, hi = struct.unpack_from("<II", raw, off)
        f = struct.unpack_from("<f", raw, off)[0]
        print("   +0x%02X  q=0x%016X  d0=0x%08X d1=0x%08X  f=%.6g" % (off, q, lo, hi, f))
