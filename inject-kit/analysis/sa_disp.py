# -*- coding: utf-8 -*-
"""sa_disp.py -- alignment-independent enumeration of every RIP-relative
memory reference whose resolved target lands in the model-context table region
[0x72BE6C0-0x400 .. 0x72BE6C0+0x10000], plus every `imul r64, r/m64, 0x34`.

Why not trust a plain linear sweep: the displacement is always the last 4 bytes
of the instruction, so for a byte offset q the instruction *end* is
(q+4)+TEXT_RVA0 and  target = end + disp32(q)  -- no need to know the
instruction length. Candidates are then validated with capstone.
"""
import struct
import numpy as np
import capstone
import sa_common as C

im = C.image()
TABLE = 0x72BE6C0
LO, HI = TABLE - 0x800, TABLE + 0x10000

MDx = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
MDx.detail = True
RIP = capstone.x86.X86_REG_RIP
MEM = capstone.x86.X86_OP_MEM


def scan_section(buf, rva0, name):
    a = np.frombuffer(buf, dtype=np.uint8)
    win = np.lib.stride_tricks.sliding_window_view(a, 4)[:-1]
    disp = win.reshape(-1, 4).copy().view(np.int32).reshape(-1)
    q = np.arange(len(disp), dtype=np.int64)
    target = rva0 + q + 4 + disp.astype(np.int64)
    sel = (target >= LO) & (target <= HI)
    idx = np.nonzero(sel)[0]
    out = []
    for qq in idx:
        qq = int(qq)
        tgt = int(target[qq])
        ok = None
        for L in range(4, 13):
            p = qq + 4 - L
            if p < 0:
                continue
            insns = list(MDx.disasm(bytes(buf[p:p + L]), rva0 + p, 1))
            if len(insns) != 1 or insns[0].size != L:
                continue
            for o in insns[0].operands:
                if o.type == MEM and o.mem.base == RIP:
                    if rva0 + p + L + o.mem.disp == tgt:
                        ok = (rva0 + p, insns[0])
                        break
            if ok:
                break
        if ok:
            out.append((ok[0], tgt, ok[1]))
    print("[%s] candidates in table region: %d (raw disp hits %d)" %
          (name, len(out), len(idx)))
    return out


res = scan_section(im.text, C.TEXT_RVA0, ".text")
res2 = scan_section(im.rdata, C.RDATA_RVA0, ".rdata")
allres = res + res2

print("\n%-12s %-12s %s" % ("insn RVA", "target", "instruction"))
for rva, tgt, insn in sorted(allres):
    print("0x%08X   0x%08X   %s %s" % (rva, tgt, insn.mnemonic, insn.op_str))

# ---------------- imul ...,0x34 ----------------
print("\n== imul r64, r/m64, 0x34 (raw scan) ==")
hits = []
t = im.text
for i in range(len(t) - 5):
    b = t[i]
    if b in (0x48, 0x49, 0x4c, 0x4d):
        if t[i + 1] == 0x6b and t[i + 3] == 0x34:
            hits.append(i)
        elif t[i + 1] == 0x69 and t[i + 3: i + 7] == b"\x34\x00\x00\x00":
            hits.append(i)
for i in hits:
    insns = list(MDx.disasm(bytes(t[i:i + 10]), C.TEXT_RVA0 + i, 1))
    if insns:
        print("0x%08X  %s %s" % (C.TEXT_RVA0 + i, insns[0].mnemonic, insns[0].op_str))

# ---------------- absolute VA of the table ----------------
tbl_va = 0x7FF689680000 + TABLE
print("\n== absolute image pointers to the table VA 0x%X ==" % tbl_va)
for sec, buf, rva0 in ((".text", im.text, C.TEXT_RVA0), (".rdata", im.rdata, C.RDATA_RVA0)):
    pat = struct.pack("<Q", tbl_va)
    j = 0
    while True:
        j = buf.find(pat, j)
        if j < 0:
            break
        print("   %s @ RVA 0x%X" % (sec, rva0 + j))
        j += 1
pat = struct.pack("<I", TABLE)
for sec, buf, rva0 in ((".text", im.text, C.TEXT_RVA0), (".rdata", im.rdata, C.RDATA_RVA0)):
    j = 0
    n = 0
    while True:
        j = buf.find(pat, j)
        if j < 0:
            break
        print("   4-byte RVA 0x%X in %s @ RVA 0x%X" % (TABLE, sec, rva0 + j))
        j += 1
        n += 1
    if n == 0:
        print("   (no 4-byte RVA value %X in %s)" % (TABLE, sec))
