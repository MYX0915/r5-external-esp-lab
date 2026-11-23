import capstone, struct
text=open(r"C:\ProgramData\scdump\69_7FF689681000.bin","rb").read()
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
base=0x1000
i=0; found=[]
while True:
    i=text.find(bytes.fromhex("486BC834"), i)
    if i<0: break
    rva=base+i
    ins=list(md.disasm(text[i:i+32], rva))
    if len(ins)>=4:
        seq=" | ".join("%s %s"%(x.mnemonic,x.op_str) for x in ins[1:4])
        found.append((rva,seq))
    i+=1
print("? %d ? imul?0x34\n" % len(found))
for rva,seq in found:
    flag=" ?" if ("rip" in seq) else ""
    print("  0x%-8X  %s%s" % (rva,seq,flag))
