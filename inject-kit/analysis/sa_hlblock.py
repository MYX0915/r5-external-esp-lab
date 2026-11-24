# -*- coding: utf-8 -*-
"""sa_hlblock.py -- map the highlight script-native block.

Method: MSVC pads functions with 0xCC (int3).  Inside [LO,HI] every maximal run
of >=2 0xCC bytes marks a function boundary; the byte after the run starts a
new function.  Each function is then disassembled completely (following
fallthrough, not ret) and written to sa_hlblock.txt.
"""
import io
import sa_common as C

im = C.image()
LO, HI = 0x2017000, 0x201A900

buf = im.text
o_lo = LO - C.TEXT_RVA0
o_hi = HI - C.TEXT_RVA0

starts = [LO]
i = o_lo
while i < o_hi - 1:
    if buf[i] == 0xCC and buf[i + 1] == 0xCC:
        j = i
        while j < o_hi and buf[j] == 0xCC:
            j += 1
        if j < o_hi:
            starts.append(C.TEXT_RVA0 + j)
        i = j
    else:
        i += 1
starts = sorted(set(starts))

out = io.StringIO()
out.write("function starts in 0x%X..0x%X: %d\n" % (LO, HI, len(starts)))
for a, b in zip(starts, starts[1:] + [HI]):
    out.write("\n%s\n### 0x%X .. 0x%X  (%d bytes)\n%s\n" %
              ("=" * 90, a, b, b - a, "=" * 90))
    ins = C.disasm(a, stop_at_ret=False, max_bytes=b - a)
    for x in ins:
        out.write(C.fmt(x) + "\n")

open("sa_hlblock.txt", "w", encoding="utf-8").write(out.getvalue())
print("starts:", " ".join("0x%X" % s for s in starts))
print("-> sa_hlblock.txt (%d bytes)" % len(out.getvalue()))
