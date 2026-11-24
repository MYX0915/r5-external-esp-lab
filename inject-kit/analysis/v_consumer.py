import capstone
text=open(r"C:\ProgramData\scdump\69_7FF689681000.bin","rb").read()
RVA0=0x1000
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
for base in (0x226D470, 0x226D600):
    print("\n=== ????? 0x%X ===" % base)
    n=0
    for ins in md.disasm(text[base-RVA0:base-RVA0+0x50], base):
        star=" <<<" if ins.mnemonic=="call" and "0x2017e50" in ins.op_str else ""
        print("  0x%08X  %-22s %s %s%s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str, star))
        n+=1
        if n>16: break
