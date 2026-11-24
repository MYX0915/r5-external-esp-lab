import capstone, re
text=open(r"C:\ProgramData\scdump\69_7FF689681000.bin","rb").read()
RVA0=0x1000
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); md.skipdata=True
print("=== ? .text ???? 0x2090 ????? 20?===")
n=0
for ins in md.disasm(text, RVA0):
    if "0x2090" in ins.op_str:
        print("  0x%08X  %-22s %s %s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
        n+=1
        if n>=20: break
print("?? %d ?" % n)
