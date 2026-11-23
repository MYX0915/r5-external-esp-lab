import capstone
text=open(r"C:\ProgramData\scdump\69_7FF689681000.bin","rb").read()
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.skipdata=True
for name,rva in (("Highlight_Enable",0x202D780), ("SetGenericHighlightContext",0x20191B0)):
    off=rva-0x1000
    print("=== %s  RVA 0x%X ===" % (name,rva))
    n=0
    for ins in md.disasm(text[off:off+0x120], rva):
        print("   0x%08X  %-24s %s %s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
        n+=1
        if n>28 or ins.mnemonic=="ret": break
    print()
