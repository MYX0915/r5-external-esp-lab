import capstone, re
text=open(r"C:\ProgramData\scdump\69_7FF689681000.bin","rb").read()
RVA0=0x1000
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); md.skipdata=True
s=0x226D800
print("=== 0x226D800 ?? 40 ???? r9 / rsp ???===")
n=0
for ins in md.disasm(text[s-RVA0:s-RVA0+0x140], s):
    op=ins.op_str
    mark=" <<<" if ("r9" in op or "0x90" in op or "0x80" in op) else ""
    print("  0x%08X  %-20s %s %s%s" % (ins.address, ins.bytes.hex(), ins.mnemonic, op, mark))
    n+=1
    if n>40: break
