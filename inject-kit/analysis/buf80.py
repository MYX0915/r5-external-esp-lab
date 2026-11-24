import capstone
text=open(r"C:\ProgramData\scdump\69_7FF689681000.bin","rb").read()
RVA0=0x1000
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); md.skipdata=True
s=0x226DA60; e=0x226DB00
print("=== 0x%X ~ 0x%X ===" % (s,e))
n=0
for ins in md.disasm(text[s-RVA0:e-RVA0], s):
    mark=" <<<" if ("0x80" in ins.op_str or "0x2090" in ins.op_str or "0x90" in ins.op_str) else ""
    print("  0x%08X  %-20s %s %s%s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str, mark))
    n+=1
    if n>26: break
