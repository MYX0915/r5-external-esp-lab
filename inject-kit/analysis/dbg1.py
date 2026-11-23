import capstone
text=open(r"C:\ProgramData\scdump\69_7FF689681000.bin","rb").read()
print("text size:", len(text))
rva=0x200BDDC
off=rva-0x1000
print("off=0x%X  bytes: %s" % (off, text[off-32:off+16].hex()))
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
start=off-0x40
n=0
for ins in md.disasm(text[start:off+0x20], rva-0x40):
    print("   0x%08X  %s %s" % (ins.address, ins.mnemonic, ins.op_str))
    n+=1
print("???:", n)
