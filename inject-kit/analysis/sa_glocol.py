# -*- coding: utf-8 -*-
"""sa_glocol.py -- 0x237F8xx writes three consecutive floats to the globals
0x72BE6E0/+4/+8 (right behind the context-table header).  Dump it to see whether
it is a global highlight-colour setter, and re-check the per-entity colour
override writers that the fixed sweep should now list.
"""
import json
import collections
import sa_common as C

print("### 0x237F780 region : writes 0x72BE6E0 / +4 / +8")
C.dump(0x237F780, stop_at_ret=False, max_bytes=0x1C0)

d = json.load(open("sa_sweep2.json"))
by = collections.defaultdict(list)
for rva, mnem, opstr, disp in d["fields"]:
    by[disp].append((rva, mnem, opstr))
for disp in (0x2bc, 0x2bd, 0x2c0, 0x2cc, 0x224, 0x298):
    print("\n== [reg + 0x%X] ==  (%d)" % (disp, len(by[disp])))
    for rva, mnem, opstr in by[disp][:24]:
        print("   0x%08X  %s %s" % (rva, mnem, opstr))
