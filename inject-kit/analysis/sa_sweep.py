# -*- coding: utf-8 -*-
"""sa_sweep.py -- single linear sweep over the whole .text section, collecting

  1. every RIP-relative operand whose resolved target is in the watchlist
     (highlight model-context table 0x72BE6C0 / its neighbourhood, the script
      VM context array 0x538ABC8, the two highlight registration strings)
  2. every `imul r64, r64, 0x34`   (entry stride 52 sites)
  3. every float store `movss/movups/movaps dword ptr [reg+disp], xmm`
     so we can later look for consecutive stores 4 bytes apart (RGB triples)
  4. every `movabs reg, imm64` with low 56 bits zero  -> VM value-type tags

Output: sa_sweep.json (+ summary on stdout)
"""
import json
import collections
import capstone
import sa_common as C

im = C.image()
MDx = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
MDx.detail = True

TABLE = 0x72BE6C0
WATCH = {
    0x72BE6C0: "TABLE_BASE",
    0x538ABC8: "VM_CTX_ARRAY",
    0x30B4418: "STR_0x7FF68C734418",
    0x30B4450: "STR_0x7FF68C734450",
}
TBL_LO, TBL_HI = TABLE - 0x400, TABLE + 0x20000

X86_MEM = capstone.x86.X86_OP_MEM
X86_REG = capstone.x86.X86_OP_REG
X86_IMM = capstone.x86.X86_OP_IMM
RIP = capstone.x86.X86_REG_RIP

text = im.text
rip_hits = []
imul34 = []
movss_writes = []
tags = collections.Counter()

CH = 1 << 20
for chunk_start in range(0, len(text), CH):
    chunk = text[chunk_start:chunk_start + CH]
    base = chunk_start + C.TEXT_RVA0
    for insn in MDx.disasm(chunk, base):
        mnem = insn.mnemonic
        ops = insn.operands
        # 4) movabs tags
        if mnem == "movabs" and len(ops) == 2 and ops[1].type == X86_IMM:
            v = ops[1].imm & 0xFFFFFFFFFFFFFFFF
            if v and (v & 0x00FFFFFFFFFFFF) == 0:
                tags[v] += 1
        # 2) imul ..., 0x34
        if mnem == "imul" and len(ops) == 3 and ops[2].type == X86_IMM and ops[2].imm == 0x34:
            rip_hits.append([insn.address, "IMUL34", insn.address + insn.size, insn.size])
            imul34.append(insn.address)
        # 1) rip-relative operands
        for o in ops:
            if o.type == X86_MEM and o.mem.base == RIP:
                t = insn.address + insn.size + o.mem.disp
                if t in WATCH:
                    rip_hits.append([insn.address, WATCH[t], t, insn.size])
                elif TBL_LO <= t <= TBL_HI:
                    rip_hits.append([insn.address, "TABLE_NEAR", t, insn.size])
                break
        # 3) float scalar/vector store to [reg+disp]
        if mnem in ("movss", "movups", "movaps", "movdqu", "movdqa") and len(ops) == 2:
            d, s = ops[0], ops[1]
            if d.type == X86_MEM and s.type == X86_REG and d.mem.base not in (0, RIP):
                movss_writes.append([insn.address, insn.size, mnem,
                                     d.mem.base, d.mem.index, d.mem.scale, d.mem.disp,
                                     s.reg])

print("decoded rip/watch hits : %d" % len(rip_hits))
print("imul ...,0x34 sites    : %d" % len(imul34))
print("float stores collected : %d" % len(movss_writes))
print("\nmovabs tag constants (low 56 bits == 0):")
for v, c in tags.most_common(40):
    print("   0x%016X  x%d" % (v, c))

json.dump({"rip_hits": rip_hits,
           "imul34": imul34,
           "movss": movss_writes,
           "tags": {("%016X" % k): v for k, v in tags.items()}},
          open("sa_sweep.json", "w"), indent=0)
print("\n-> sa_sweep.json")
