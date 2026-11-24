import capstone, re
text=open(r"C:\ProgramData\scdump\69_7FF689681000.bin","rb").read()
RVA0=0x1000
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); md.skipdata=True
s=0x226D800; e=0x226DB80
print("=== 0x226D800~0x226DB80 ??? rdi ??? ===")
n=0
for ins in md.disasm(text[s-RVA0:e-RVA0], s):
    if re.search(r'\brdi\b', ins.op_str):
        print("  0x%08X  %-20s %s %s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
        n+=1
        if n>25: break
print("\n? %d ????25?" % n)
