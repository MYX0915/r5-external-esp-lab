import capstone
text=open(r"C:\ProgramData\scdump\69_7FF689681000.bin","rb").read()
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
rva=0x202D739
off=rva-0x1000
for ins in md.disasm(text[off-0x60:off+0x10], rva-0x60):
    mark="  <<< call" if abs(ins.address-rva)<3 else ""
    print("   0x%08X  %-24s %s %s%s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str, mark))
