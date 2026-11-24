# -*- coding: utf-8 -*-
"""sa_strings.py -- read the highlight-related strings out of .rdata and find
every place that references them (ptr table = native-function registration).

Strings given in the brief:
   VA 0x7FF68C734418  -> .rdata off 0x410418 -> RVA 0x30B4418
   VA 0x7FF68C734450  -> .rdata off 0x410450 -> RVA 0x30B4450
"""
import struct
import sa_common as C

im = C.image()

STR1_RVA = 0x30B4418
STR2_RVA = 0x30B4450
RD_BASE_VA = 0x7FF68C324000


def cstr(rva, maxlen=96):
    b = im.read(rva, maxlen)
    if not b:
        return "<unreadable>"
    z = b.find(b"\x00")
    return b[:z if z >= 0 else maxlen].decode("latin1")


print("== .rdata 0x30B4380 .. 0x30B4580 (null-terminated strings) ==")
rva = 0x30B4380
while rva < 0x30B4580:
    s = cstr(rva)
    if s:
        print("  0x%08X  %r" % (rva, s))
        rva += len(s) + 1
    else:
        rva += 1

print("\n== pointer references to the two strings ==")
targets = {}
for rva in range(0x30B4300, 0x30B4600):
    s = cstr(rva)
    if s.startswith("Highlight") or s.startswith("highlight"):
        targets[rva] = s

for str_rva, name in sorted(targets.items()):
    as_va = RD_BASE_VA + (str_rva - C.RDATA_RVA0)
    needle_rva = struct.pack("<Q", str_rva)
    needle_va = struct.pack("<Q", as_va)
    hits = []
    for section, size, base_rva in ((".text", C.TEXT_SIZE, C.TEXT_RVA0),
                                    (".rdata", C.RDATA_SIZE, C.RDATA_RVA0)):
        buf = im.text if section == ".text" else im.rdata
        for pat, kind in ((needle_rva, "RVA-ptr"), (needle_va, "VA-ptr")):
            i = 0
            while True:
                i = buf.find(pat, i)
                if i < 0:
                    break
                hits.append((section, base_rva + i, kind))
                i += 1
    print("\n  %-46r RVA 0x%X  VA 0x%X" % (name, str_rva, as_va))
    if not hits:
        print("     (no pointer references found)")
    for sec, hrva, kind in hits:
        print("     %s @ RVA 0x%08X  (%s)" % (sec, hrva, kind))
