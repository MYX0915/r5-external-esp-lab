import capstone
text=open(r"C:\ProgramData\scdump\2_7FF776981000.bin","rb").read()
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
rva=0x209A127
off=rva-0x1000
for ins in md.disasm(text[off-0x80:off+0x20], rva-0x80):
    mark="  <<< call" if abs(ins.address-rva)<2 else ""
    print("  0x%08X  %-22s %s %s%s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str, mark))
