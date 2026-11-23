import capstone, struct
text=open(r"C:\ProgramData\scdump\69_7FF689681000.bin","rb").read()
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
base=0x1000
spots=[0x23CE83C,0x23CE914,0x23CEA9C,0x23CEB39,0x23CEBD9,0x23CEC97,0x23CED25,0x23CEDFF,0x23CEEDF,0x23CEFDF]
out=[]
for rva in spots:
    off=rva-0x1000
    ins=list(md.disasm(text[off-4:off+8], rva-4))
    for x in ins:
        if x.address==rva and "rip" in x.op_str:
            import re
            m=re.search(r'rip \+ (0x[0-9a-f]+)', x.op_str)
            if m:
                disp=int(m.group(1),16)
                tgt=x.address+x.size+disp
                out.append((rva,tgt,x.mnemonic+" "+x.op_str))
print("rip ????:")
for rva,tgt,ins in out:
    print("   RVA 0x%-8X ? ?? RVA 0x%-9X   (%s)" % (rva,tgt,ins))
open("globs.txt","w").write("\n".join("%d"%t for _,t,_ in out))
