import capstone
data=open(r"C:\ProgramData\scdump\15_7FF687CC1000.bin","rb").read()
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail=False
def dump(rva, back, fwd, label):
    start=rva-back
    print("=== %s  (RVA 0x%X) ===" % (label, rva))
    for ins in md.disasm(data[start:rva+fwd], start):
        mark = "  <<<" if abs(ins.address-rva)<8 else ""
        print("  0x%08X  %-24s %s %s%s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str, mark))
    print()
dump(0x23FF631, 0x60, 0x30, "subss xmm0,[rdi+0x376C]")
