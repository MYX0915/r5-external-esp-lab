import capstone
text=open(r"C:\ProgramData\scdump\69_7FF689681000.bin","rb").read()
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
for rva in (0x1C6D166, 0x21A83F1, 0x21A8553):
    off=rva-0x1000
    print("=== RVA 0x%X ===" % rva)
    for ins in md.disasm(text[off-8:off+40], rva-8):
        mark="  <<<" if abs(ins.address-rva)<4 else ""
        print("   0x%08X  %-24s %s %s%s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str, mark))
    print()
