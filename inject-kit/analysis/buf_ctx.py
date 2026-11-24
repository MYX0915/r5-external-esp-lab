import capstone
text=open(r"C:\ProgramData\scdump\69_7FF689681000.bin","rb").read()
RVA0=0x1000
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.skipdata=True
for center,label in ((0x226D9E8,"buf A [rsp+0x90]"), (0x226DA39,"buf C [rsp+0x4090]")):
    print("=== %s  ?? 0x%X ===" % (label,center))
    s=center-0x20
    n=0
    for ins in md.disasm(text[s-RVA0:center-RVA0+0x40], s):
        star=" <<< lea" if abs(ins.address-center)<2 else ""
        print("  0x%08X  %-22s %s %s%s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str, star))
        n+=1
        if n>20: break
    print()
