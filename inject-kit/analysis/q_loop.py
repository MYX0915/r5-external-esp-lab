import capstone, re
text=open(r"C:\ProgramData\scdump\69_7FF689681000.bin","rb").read()
RVA0=0x1000
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.skipdata=True
entry=0x226D0F0
print("=== r14 / r13 / r12 ??????0x%X ??? 0x600 ???===" % entry)
cnt=0
for ins in md.disasm(text[entry-RVA0:entry-RVA0+0x600], entry):
    op=ins.op_str
    if re.search(r'\b(r14|r13|r12)\b', op):
        print("  0x%08X  %-22s %s %s" % (ins.address, ins.bytes.hex(), ins.mnemonic, op))
        cnt+=1
        if cnt>28: break
