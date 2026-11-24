# -*- coding: utf-8 -*-
"""sa_extract.py -- final extraction pass for the report.

 * dump the validated `imul ...,0x34` list and the table-region reference list
 * dump the highlight-field access sites (clean [reg+disp], no index)
 * locate the real start of the function containing 0x200FAFD (the routine that
   writes every highlight colour field on the entity)
"""
import json
import collections
import sa_common as C

d = json.load(open("sa_sweep2.json"))
calls = json.load(open("sa_calls.json"))
targets = sorted(int(k, 16) for k in calls)

print("== imul r64, r/m64, 0x34 (validated) ==")
for rva, s in d["imul34"]:
    print("   0x%08X  imul %s" % (rva, s))

print("\n== references into the model-context table region [0x72BE6C0-0x800..+0x10000] ==")
for rva, t, s in sorted(d["tblrefs"]):
    print("   0x%08X -> 0x%09X  %s" % (rva, t, s))

WANT = [0x298, 0x2a0, 0x2a8, 0x2bc, 0x2bd, 0x2c0, 0x2c4, 0x2c8, 0x2cc,
        0x2d0, 0x2d4, 0x224, 0x228, 0x22c, 0x230, 0x234, 0x238,
        0x240, 0x24c, 0x250, 0x254, 0x33c, 0x32c, 0x19c, 0x256]
by = collections.defaultdict(list)
for rva, mnem, opstr, disp in d["fields"]:
    by[disp].append((rva, mnem, opstr))
for disp in WANT:
    v = by.get(disp, [])
    print("\n== [reg + 0x%X] : %d ==" % (disp, len(v)))
    for rva, mnem, opstr in v:
        print("   0x%08X  %s %s" % (rva, mnem, opstr))


def find_start(rva):
    """nearest previous function start = last address below rva that is a call
    target, or the byte after a >=2 long 0xCC run."""
    cand = [t for t in targets if rva - 0x800 <= t <= rva]
    best = max(cand) if cand else None
    buf = C.image().text
    o = rva - C.TEXT_RVA0
    i = o
    while i > o - 0x800:
        if buf[i - 1] == 0xCC and buf[i - 2] == 0xCC:
            pad = C.TEXT_RVA0 + i
            if best is None or pad > best:
                best = pad
            break
        i -= 1
    return best


for probe in (0x200FAFD, 0x200FB7F, 0x2004B2D):
    print("\nprobe 0x%X -> function start 0x%X" % (probe, find_start(probe) or 0))
