# -*- coding: utf-8 -*-
"""sa_fields.py -- single .text sweep that indexes every instruction touching an
interesting entity field, so we can answer "who writes the colour".

watch displacements (entity-relative):
  0x298  generic highlight context id (byte, *pointed to*)
  0x2a0..0x2a3 / 0x2a8   inherit-highlight slots + mask
  0x2bc 0x2bd            per-entity colour-override enable bytes
  0x2c0..0x2d7           per-entity override colours (outline / inside)
  0x224..0x23b           current outline / inside colour vectors
  0x33c 0x32c            highlight flag dwords (bit1 used as gate)
  0x240 0x24c 0x250 0x254  cached context params
  0x1 0x8 0x138 0x128   entity id / parent handle
Also collects consecutive `movss dword[reg+d], xmm` triples whose displacements
are 4 apart (RGB patterns).
"""
import json
import collections
import capstone
import sa_common as C

im = C.image()
MDx = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
MDx.detail = True

WATCH = {}
for d in (0x298, 0x2a0, 0x2a1, 0x2a2, 0x2a3, 0x2a8, 0x2bc, 0x2bd,
          0x2c0, 0x2c4, 0x2c8, 0x2cc, 0x2d0, 0x2d4, 0x224, 0x228, 0x22c,
          0x230, 0x234, 0x238, 0x33c, 0x32c, 0x240, 0x24c, 0x250, 0x254,
          0x1, 0x8, 0x138, 0x128, 0x19c, 0x256, 0x260, 0x280, 0x288):
    WATCH[d] = True

MEM = capstone.x86.X86_OP_MEM
REG = capstone.x86.X86_OP_REG

hits = []
float_seq = []
buf = im.text
CH = 1 << 20
for cs in range(0, len(buf), CH):
    for insn in MDx.disasm(buf[cs:cs + CH], C.TEXT_RVA0 + cs):
        ops = insn.operands
        if not ops:
            continue
        d = ops[0]
        if d.type == MEM and d.mem.disp in WATCH and d.mem.base != 0 \
                and d.mem.base != capstone.x86.X86_REG_RIP:
            hits.append([insn.address, insn.mnemonic, insn.op_str, d.mem.disp])
        if insn.mnemonic in ("movss", "movsd") and d.type == MEM \
                and len(ops) == 2 and ops[1].type == REG:
            float_seq.append([insn.address, d.mem.base, d.mem.disp, insn.mnemonic])

print("field hits: %d" % len(hits))

by = collections.defaultdict(list)
for h in hits:
    by[h[3]].append(h)
for disp in sorted(by):
    print("\n=== disp 0x%X : %d sites ===" % (disp, len(by[disp])))
    for rva, mnem, opstr, _ in by[disp]:
        print("   0x%08X  %s %s" % (rva, mnem, opstr))

# consecutive float stores 4 apart with the same base register
tri = []
fs = sorted(float_seq)
for i in range(len(fs) - 2):
    a, ra, da, ma = fs[i]
    b, rb, db, mb = fs[i + 1]
    c, rc, dc, mc = fs[i + 2]
    if ra == rb == rc and db - da == 4 and dc - db == 4:
        tri.append((a, ra, da))
print("\nconsecutive movss triples (disp +4 steps, same base): %d" % len(tri))
for rva, base, disp in tri:
    ins = list(MDx.disasm(im.text[im.rva2off(rva - 6):im.rva2off(rva) + 30], rva - 6))
    print("   triple at 0x%08X base=%s disp=0x%X" %
          (rva, MDx.reg_name(base), disp))

json.dump({"hits": hits, "triples": tri}, open("sa_fields.json", "w"))
print("\n-> sa_fields.json")
