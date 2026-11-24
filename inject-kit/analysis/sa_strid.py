# -*- coding: utf-8 -*-
"""sa_strid.py -- the highlight script names have no 8-byte pointer reference,
so look for 4-byte RVA references and for the name-block layout; also list the
whole contiguous name block so the registration order is visible.
"""
import struct
import sa_common as C

im = C.image()

for str_rva, name in ((0x30B4418, "Highlight_Enable"),
                      (0x30B4450, "Highlight_SetGenericHighlightContext"),
                      (0x30B4430, "Highlight_GetInheritHighlight"),
                      (0x30B4478, "Highlight_SetCurrentContext")):
    print("== 4-byte RVA references to 0x%X (%s) ==" % (str_rva, name))
    pat = struct.pack("<I", str_rva)
    for sec, buf, base in ((".text", im.text, C.TEXT_RVA0), (".rdata", im.rdata, C.RDATA_RVA0)):
        i = 0
        n = 0
        while True:
            i = buf.find(pat, i)
            if i < 0:
                break
            print("   %s @ RVA 0x%08X" % (sec, base + i))
            i += 1
            n += 1
        if n == 0:
            print("   %s: none" % sec)
    print()

# any other occurrence of the literal name bytes anywhere in the image?
needle = b"Highlight_Enable\x00"
for sec, buf, base in ((".text", im.text, C.TEXT_RVA0), (".rdata", im.rdata, C.RDATA_RVA0)):
    i = 0
    while True:
        i = buf.find(needle, i)
        if i < 0:
            break
        print("literal 'Highlight_Enable' in %s @ RVA 0x%X" % (sec, base + i))
        i += 1
