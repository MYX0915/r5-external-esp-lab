import capstone
from capstone.x86 import X86_OP_MEM, X86_REG_RIP
text=open(r"C:\ProgramData\scdump\2_7FF776981000.bin","rb").read()
targets=set()
for line in open("camglobals.txt"):
    targets.add(int(line))
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail=True
hits=[]
for ins in md.disasm(text, 0x1000):
    for op in ins.operands:
        if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
            t = ins.address + ins.size + op.mem.disp
            if t in targets:
                hits.append((ins.address, ins.mnemonic, ins.op_str))
                break
print("references to camera globals:", len(hits))
from collections import Counter
c=Counter(h[0]>>12 for h in hits)
print("hot 4KB pages:")
for pg,n in c.most_common(8):
    print("   page 0x%06X  refs=%d" % (pg<<12, n))
for a,m,o in hits[:20]:
    print("   0x%08X  %s %s" % (a,m,o))
