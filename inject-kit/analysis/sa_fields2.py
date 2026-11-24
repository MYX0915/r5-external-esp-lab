# -*- coding: utf-8 -*-
"""sa_fields2.py -- filter sa_fields.json down to clean entity-field accesses
(no index register, i.e. really [reg+disp]) that WRITE something, excluding the
ubiquitous disp 0x1/0x8 noise.
"""
import json
import collections
import capstone
import sa_common as C

MDx = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
MDx.detail = True
im = C.image()

d = json.load(open("sa_fields.json"))
hits = d["hits"]
WRITE = ("mov", "movss", "movsd", "movups", "movaps", "or", "and", "bts", "btr",
         "xor", "inc", "dec", "add", "sub", "movzx")

by = collections.defaultdict(list)
for rva, mnem, opstr, disp in hits:
    if " + r" in opstr.split("]")[0] or "*" in opstr.split("]")[0]:
        continue
    by[disp].append((rva, mnem, opstr))

for disp in sorted(by):
    if disp in (0x1, 0x8):
        continue
    print("\n=== [reg + 0x%X] : %d sites ===" % (disp, len(by[disp])))
    for rva, mnem, opstr in by[disp][:40]:
        tail = ""
        if mnem.startswith("mov") and opstr.split(",")[0].strip().startswith("dword"):
            tail = "   <-- WRITE"
        if mnem in ("or", "and", "bts", "btr", "xor", "inc", "dec") and ", [" not in opstr:
            if "[r" in opstr.split(",")[0]:
                tail = "   <-- WRITE"
        print("   0x%08X  %s %s%s" % (rva, mnem, opstr, tail))

print("\n=== consecutive movss triples (disp+4) ===")
for rva, base, disp in d["triples"]:
    print("   0x%08X base=%s disp=0x%X" % (rva, MDx.reg_name(base), disp))
