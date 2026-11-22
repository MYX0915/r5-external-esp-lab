import capstone
data=open(r"C:\ProgramData\scdump\2_7FF776981000.bin","rb").read()
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
def show(rva, back=0x30, fwd=0x50):
    print("=== around RVA 0x%X ===" % rva)
    for ins in md.disasm(data[rva-back:rva+fwd], rva-back):
        print("  0x%08X  %-24s %s %s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
show(0x23E6176)
