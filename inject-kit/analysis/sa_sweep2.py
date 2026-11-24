# -*- coding: utf-8 -*-
"""sa_sweep2.py -- robust .text index.

Chunked disassembly desynchronises (a chunk that starts mid-instruction decodes
garbage for its whole length), so this version walks the section in one pass
using a *recursive-descent-lite* strategy:

  * candidate function starts = every validated direct-call target (sa_calls)
    plus 0x1000 (section start)
  * starts are visited in ascending order; already covered bytes are skipped,
    so each function is decoded exactly once and decoding is always aligned to a
    real instruction boundary.

Collected:
  T1  every `imul r64, r/m64, 0x34`
  T2  every instruction whose first operand is [reg+disp] (no index) with
      disp in the highlight watch set
  T3  every RIP-relative operand target inside the model-context table region
  T4  consecutive float stores 4 bytes apart (RGB triples)
"""
import json
import collections
import capstone
import sa_common as C

im = C.image()
MDx = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
MDx.detail = True
MDx.skipdata = False

MEM = capstone.x86.X86_OP_MEM
REG = capstone.x86.X86_OP_REG
IMM = capstone.x86.X86_OP_IMM
RIP = capstone.x86.X86_REG_RIP

TABLE = 0x72BE6C0
TBL_LO, TBL_HI = TABLE - 0x800, TABLE + 0x10000
WATCH = set([0x298, 0x2a0, 0x2a1, 0x2a2, 0x2a3, 0x2a8, 0x2bc, 0x2bd,
             0x2c0, 0x2c4, 0x2c8, 0x2cc, 0x2d0, 0x2d4,
             0x224, 0x228, 0x22c, 0x230, 0x234, 0x238,
             0x240, 0x24c, 0x250, 0x254, 0x33c, 0x32c, 0x19c, 0x256])

calls = json.load(open("sa_calls.json"))
starts = set([0x1000])
for k in calls:
    starts.add(int(k, 16))
starts = sorted(s for s in starts if C.TEXT_RVA0 <= s < C.TEXT_RVA0 + C.TEXT_SIZE)
print("candidate function starts: %d" % len(starts))

imul34, fields, tblrefs, floats = [], [], [], []
cursor = C.TEXT_RVA0
decoded = 0

buf = im.text
for st in starts:
    if st < cursor:
        continue
    insns = MDx.disasm(buf[st - C.TEXT_RVA0: st - C.TEXT_RVA0 + 0x4000], st)
    for insn in insns:
        decoded += 1
        cursor = insn.address + insn.size
        if insn.address + insn.size > C.TEXT_RVA0 + C.TEXT_SIZE:
            break
        try:
            ops = insn.operands
        except Exception:
            continue
        # T1
        if insn.mnemonic == "imul" and len(ops) == 3 and ops[2].type == IMM and ops[2].imm == 0x34:
            imul34.append([insn.address, insn.op_str])
        # T2
        if ops and ops[0].type == MEM and ops[0].mem.base not in (0, RIP) \
                and ops[0].mem.index == 0 and ops[0].mem.disp in WATCH:
            fields.append([insn.address, insn.mnemonic, insn.op_str, ops[0].mem.disp])
        # T3
        for o in ops:
            if o.type == MEM and o.mem.base == RIP:
                t = insn.address + insn.size + o.mem.disp
                if TBL_LO <= t <= TBL_HI:
                    tblrefs.append([insn.address, t, insn.mnemonic + " " + insn.op_str])
                break
        # T4
        if insn.mnemonic in ("movss", "movsd") and len(ops) == 2 \
                and ops[0].type == MEM and ops[1].type == REG and ops[0].mem.index == 0:
            floats.append([insn.address, ops[0].mem.base, ops[0].mem.disp])
        if insn.mnemonic.startswith("ret") or insn.mnemonic == "int3":
            break

print("decoded %d instructions, coverage to RVA 0x%X" % (decoded, cursor))
print("imul 0x34 : %d" % len(imul34))
print("field hits: %d" % len(fields))
print("table refs: %d" % len(tblrefs))
print("float stores: %d" % len(floats))

tri = []
for i in range(len(floats) - 2):
    a, ra, da = floats[i]
    b, rb, db = floats[i + 1]
    c, rc, dc = floats[i + 2]
    if ra == rb == rc and db - da == 4 and dc - db == 4:
        tri.append([a, ra, da])

json.dump({"imul34": imul34, "fields": fields, "tblrefs": tblrefs,
           "triples": tri}, open("sa_sweep2.json", "w"))

print("\n== imul 0x34 ==")
for rva, s in imul34:
    print("   0x%08X  imul %s" % (rva, s))
print("\n== table refs ==")
for rva, t, s in sorted(tblrefs):
    print("   0x%08X -> 0x%09X  %s" % (rva, t, s))
print("\n== float triples ==")
for rva, base, disp in tri:
    print("   0x%08X base=%s disp=0x%X" % (rva, MDx.reg_name(base), disp))
