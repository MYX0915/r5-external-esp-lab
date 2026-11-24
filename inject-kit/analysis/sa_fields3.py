# -*- coding: utf-8 -*-
"""sa_fields3.py -- print only the highlight-specific displacements."""
import json
import collections
import sa_common as C

WANT = [0x298, 0x2a0, 0x2a1, 0x2a2, 0x2a3, 0x2a8, 0x2bc, 0x2bd,
        0x2c0, 0x2c4, 0x2c8, 0x2cc, 0x2d0, 0x2d4,
        0x33c, 0x32c, 0x24c, 0x250, 0x254, 0x288, 0x280]
d = json.load(open("sa_fields.json"))
by = collections.defaultdict(list)
for rva, mnem, opstr, disp in d["hits"]:
    head = opstr.split("]")[0]
    if "+ r" in head or "*" in head:
        continue
    by[disp].append((rva, mnem, opstr))

for disp in WANT:
    v = by.get(disp, [])
    if not v:
        continue
    print("\n=== [reg + 0x%X] : %d sites ===" % (disp, len(v)))
    for rva, mnem, opstr in v:
        print("   0x%08X  %s %s" % (rva, mnem, opstr))
