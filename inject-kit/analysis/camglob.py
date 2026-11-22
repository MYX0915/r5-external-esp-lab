import capstone
from capstone.x86 import X86_OP_MEM, X86_REG_RIP
text=open(r"C:\ProgramData\scdump\2_7FF776981000.bin","rb").read()
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail=True
lo, hi = 0x23E7000, 0x23E7300
globs=[]
for ins in md.disasm(text[lo-0x1000:hi-0x1000], lo):
    for op in ins.operands:
        if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
            tgt = ins.address + ins.size + op.mem.disp
            globs.append((tgt, ins.address, ins.mnemonic, ins.op_str))
print("rip targets in view-state fn:", len(globs))
seen=set()
for t,a,m,o in globs:
    if t in seen: continue
    seen.add(t)
    print("   global RVA 0x%-8X  <- 0x%08X  %s %s" % (t,a,m,o))
open("camglobals.txt","w").write("\n".join("%d"%t for t in sorted(seen)))
