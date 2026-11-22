import capstone
text=open(r"C:\ProgramData\scdump\2_7FF776981000.bin","rb").read()
print("text MB:", round(len(text)/1048576,1))
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.skipdata = True
hits=[]
n=0
for ins in md.disasm(text, 0):
    n+=1
    if "0x1f78" in ins.op_str or "0x1f84" in ins.op_str:
        hits.append((ins.address, ins.mnemonic, ins.op_str))
    if len(hits)>=200: break
print("disassembled:", n, " hits:", len(hits))
for a,m,o in hits[:25]:
    print("  0x%08X  %s %s" % (a,m,o))
