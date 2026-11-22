import capstone
text=open(r"C:\ProgramData\scdump\2_7FF776981000.bin","rb").read()
s=0x2884990; size=5516
i=text.find(bytes.fromhex("781F0000"), s, s+size)
print("cam ref at 0x%X (offset in func 0x%X)" % (i, i-s))
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
a=i-0x50
for x in md.disasm(text[a:i+0x30], a):
    mark="  <<<" if "0x1f78" in x.op_str else ""
    print("  0x%08X  %-22s %s %s%s" % (x.address, x.bytes.hex(), x.mnemonic, x.op_str, mark))
