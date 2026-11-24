# -*- coding: utf-8 -*-
"""sa_calls.py -- build a call/xref index for the whole .text (validated with
capstone), then print callers of the highlight functions.

  E8 rel32   direct call
  E9 rel32   direct jmp
  FF /2, FF /4 indirect call / jmp (reported, target unknown)
"""
import json
import collections
import capstone
import sa_common as C

im = C.image()
MDx = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
MDx.detail = True

buf = im.text
n = len(buf)
calls = collections.defaultdict(list)   # target rva -> [site rva]
sites = 0

i = 0
OP_CALL = capstone.x86.X86_INS_CALL
OP_JMP = capstone.x86.X86_INS_JMP
while True:
    i = buf.find(b"\xe8", i)
    if i < 0:
        break
    ins = list(MDx.disasm(buf[i:i + 5], C.TEXT_RVA0 + i, 1))
    if ins and ins[0].id == OP_CALL and len(ins[0].operands) == 1 \
            and ins[0].operands[0].type == capstone.x86.X86_OP_IMM:
        calls[ins[0].operands[0].imm].append(C.TEXT_RVA0 + i)
        sites += 1
    i += 1

print("validated direct calls: %d unique targets: %d" % (sites, len(calls)))
json.dump({("%X" % k): v for k, v in calls.items()}, open("sa_calls.json", "w"))


def callers(target, limit=40):
    v = calls.get(target, [])
    print("\n== callers of 0x%X : %d ==" % (target, len(v)))
    for s in v[:limit]:
        print("   from 0x%X" % s)
    return v


for t, name in ((0x2017E50, "BuildHighlightDescriptor"),
                (0x2017C60, "opacity/scale helper"),
                (0x2018130, "current-color packer"),
                (0x202D780, "Highlight_Enable (script native)"),
                (0x202D700, "SetGenericHighlightContext wrapper"),
                (0x20191B0, "Highlight_SetGenericHighlightContext")):
    callers(t)
