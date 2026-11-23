import capstone
text=open(r"C:\ProgramData\scdump\69_7FF689681000.bin","rb").read()
TEXT_VA=0x7FF689681000
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
for rva in (0x200BDDC, 0x200BF20):
    off=(TEXT_VA + rva - 0x1000) - TEXT_VA
    print("=== RVA 0x%X ===" % rva)
    for ins in md.disasm(text[off-0x40:off+0x20], rva-0x40):
        mark="  <<< ???" if abs(ins.address-rva)<6 else ""
        print("   0x%08X  %-22s %s %s%s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str, mark))
    print()
