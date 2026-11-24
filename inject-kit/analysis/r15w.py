import capstone, re
text=open(r"C:\ProgramData\scdump\69_7FF689681000.bin","rb").read()
RVA0=0x1000
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.skipdata=True
T=0x226CDE0
print("=== 0x%X ????? r15 ??? ===" % T)
n=0
for ins in md.disasm(text[T-RVA0:T-RVA0+0x400], T):
    if re.search(r'\br15\b', ins.op_str):
        kind="?" if ins.op_str.split(",")[0].strip().startswith(("word","byte","dword","qword","[")) and "ptr [r15" in ins.op_str.split(",")[0] else ""
        print("  %s0x%08X  %-22s %s %s" % (kind, ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
        n+=1
        if n>22: break
