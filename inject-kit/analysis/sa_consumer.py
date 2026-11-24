# -*- coding: utf-8 -*-
"""sa_consumer.py -- final evidence:
  * 0x226D450.. : the render-side consumer that calls BuildHighlightDescriptor
  * IAT slots used as lock/unlock by SetGenericHighlightContext and the
    entity-state copy routine
  * the float / global constants the builder uses
"""
import struct
import sa_common as C

im = C.image()

print("### consumer 0x226D450 region")
C.dump(0x226D450, stop_at_ret=False, max_bytes=0x210)

print("\n### IAT slots")
for rva in (0x2CA4B48, 0x2CA4B50):
    q = im.qword(rva)
    print("   0x%X : qword 0x%X" % (rva, q))

print("\n### constants")
for rva in (0x32024DC, 0x32022E8, 0x3201FCC, 0x3202990, 0x3202B64,
            0x3202208, 0x3D3A8D0, 0x3D3A8D2):
    b = im.read(rva, 4)
    if not b:
        print("   0x%X : <unreadable>" % rva)
        continue
    u = struct.unpack("<I", b)[0]
    f = struct.unpack("<f", b)[0]
    w = struct.unpack("<H", b[:2])[0]
    print("   0x%X : u=0x%08X w=0x%04X f=%.6g" % (rva, u, w, f))

print("\n### module base check: RVA 0x72BE6C0 -> VA 0x%X" % (0x7FF689680000 + 0x72BE6C0))
print("### .rdata string RVA 0x30B4418 -> VA 0x%X" % (0x7FF68C324000 + (0x30B4418 - 0x2CA4000)))
