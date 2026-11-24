# -*- coding: utf-8 -*-
"""sa_refs.py -- analyse sa_sweep.json: every reference to the model-context
table 0x72BE6C0 (and to its neighbourhood), plus every imul ...,0x34 site.

For each hit the surrounding instruction window is printed so the role of the
site (index computation / table read / table write / count read) is visible.
"""
import json
import collections
import capstone
import sa_common as C

im = C.image()
d = json.load(open("sa_sweep.json"))
hits = d["rip_hits"]
imul34 = d["imul34"]

by_note = collections.Counter()
for rva, note, tgt, size in hits:
    by_note[note] += 1
print("hits by note:", dict(by_note))
print("imul34 list  :", ["0x%X" % x for x in imul34])

TABLE = 0x72BE6C0


def window(rva, before=0x30, after=0x30):
    """disassemble a window around rva and return list of (insn, is_target)"""
    start = rva - before
    ins = C.disasm(start, stop_at_ret=False, max_bytes=before + after)
    return ins


def show(label, rva, before=0x28, after=0x30):
    print("\n--- %s  @ 0x%X ---" % (label, rva))
    ins = window(rva, before, after)
    for i in ins:
        mark = " <<<" if i.address == rva else ""
        print(C.fmt(i) + mark)


print("\n" + "=" * 90)
print("A. references resolving exactly to 0x72BE6C0")
exact = sorted([h for h in hits if h[1] == "TABLE_BASE"], key=lambda x: x[0])
for rva, note, tgt, size in exact:
    show("TABLE_BASE", rva, 0x20, 0x20)

print("\n" + "=" * 90)
print("B. references into the table neighbourhood")
near = sorted([h for h in hits if h[1] == "TABLE_NEAR"], key=lambda x: x[0])
print("%d hits" % len(near))
c = collections.Counter(h[2] for h in near)
for tgt, n in c.most_common(30):
    print("   target 0x%08X : %d" % (tgt, n))

print("\n" + "=" * 90)
print("C. other watchlist references")
for rva, note, tgt, size in sorted([h for h in hits if h[1] not in ("TABLE_BASE", "TABLE_NEAR")], key=lambda x: x[0]):
    show("%s -> 0x%X" % (note, tgt), rva, 0x18, 0x18)

print("\n" + "=" * 90)
print("D. imul ...,0x34 sites")
for rva in imul34:
    show("IMUL34", rva, 0x30, 0x40)
