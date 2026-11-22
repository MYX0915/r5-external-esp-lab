import capstone, struct
text=open(r"C:\ProgramData\scdump\2_7FF776981000.bin","rb").read()
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
s=0x2884990
ins=list(md.disasm(text[s:s+0x1A0], s))
print("first 40 instructions of 0x%X:" % s)
for i,x in enumerate(ins[:40]):
    mark = "  <<< cam ref" if "0x1f78" in x.op_str else ""
    print("  0x%08X  %-22s %s %s%s" % (x.address, x.bytes.hex(), x.mnemonic, x.op_str, mark))
