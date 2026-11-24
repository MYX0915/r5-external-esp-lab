import capstone
text=open(r"C:\ProgramData\scdump\69_7FF689681000.bin","rb").read()
RVA0=0x1000
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
s=0x226D3F0
print("=== 0x%X ~ 0x226D490 ===" % s)
n=0
for ins in md.disasm(text[s-RVA0:0x226D490-RVA0], s):
    print("  0x%08X  %-22s %s %s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
    n+=1
    if n>34: break
