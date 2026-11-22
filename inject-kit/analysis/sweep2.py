import capstone, re
text=open(r"C:\ProgramData\scdump\2_7FF776981000.bin","rb").read()
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.skipdata = True
pat=re.compile(r"\+ 0x1f(78|84)\]$")
hits=[]
for ins in md.disasm(text, 0):
    if pat.search(ins.op_str):
        hits.append((ins.address, ins.mnemonic, ins.op_str))
print("exact field refs:", len(hits))
for a,m,o in hits[:30]:
    print("  0x%08X  %s %s" % (a,m,o))
