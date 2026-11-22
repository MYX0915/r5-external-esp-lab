import capstone
text=open(r"C:\ProgramData\scdump\2_7FF776981000.bin","rb").read()
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
spots=[0x828216,0x159a74e,0x1524227,0x174ae20,0xdb8f46,0x1ffb6e9]
for rva in spots:
    off=rva-0x1000
    print("=== RVA 0x%X ===" % rva)
    a=off-0x30
    for ins in md.disasm(text[a:off+0x40], rva-0x30):
        mark="  <<<" if abs(ins.address-rva)<4 else ""
        print("   0x%08X  %-20s %s %s%s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str, mark))
    print()
