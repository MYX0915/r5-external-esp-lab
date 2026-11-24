import capstone
text=open(r"C:\ProgramData\scdump\69_7FF689681000.bin","rb").read()
RVA0=0x1000
s=0x2017EA8; e=0x2017F20
seg=text[s-RVA0:e-RVA0]
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
print("=== 0x%X ?????? ===" % s)
for i,ins in enumerate(md.disasm(seg, s)):
    if i>22: break
    print("  0x%08X  %-22s %s %s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
