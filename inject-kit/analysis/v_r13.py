import capstone
text=open(r"C:\ProgramData\scdump\69_7FF689681000.bin","rb").read()
RVA0=0x1000
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
# ??? r13 / r14 ???
s=0x226D200
hits=[]
for ins in md.disasm(text[s-RVA0:0x226D410-RVA0], s):
    op=ins.op_str
    if ins.mnemonic in ("mov","lea") and (op.startswith("r13,") or op.startswith("r14,")):
        hits.append(ins)
    elif ins.mnemonic=="mov" and ", r13" in op:
        pass
print("=== r13 / r14 ????0x%X~0x226D410?===" % s)
for ins in hits[-12:]:
    print("  0x%08X  %-22s %s %s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
# ?????
i=0x226D200
while i>0x226D000:
    if text[i-RVA0]==0xCC:
        print("\n????(CC ?): 0x%X" % (i+1)); break
    i-=1
