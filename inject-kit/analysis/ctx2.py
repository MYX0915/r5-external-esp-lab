import capstone
text=open(r"C:\ProgramData\scdump\2_7FF776981000.bin","rb").read()
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
# dump the first 0x60 bytes of 0x209A0D0 to see the arg source
rva=0x209A0D0; off=rva-0x1000
for ins in md.disasm(text[off:off+0x40], rva):
    print("  0x%08X  %-22s %s %s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
