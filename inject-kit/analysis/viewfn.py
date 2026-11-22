import capstone
text=open(r"C:\ProgramData\scdump\2_7FF776981000.bin","rb").read()
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
s=0x23E6085
a=s-0x60
for x in md.disasm(text[a:s+0x40], a):
    mark="  <<<" if ("0x1f78" in x.op_str or "0x1f84" in x.op_str) else ""
    print("  0x%08X  %-22s %s %s%s" % (x.address, x.bytes.hex(), x.mnemonic, x.op_str, mark))
