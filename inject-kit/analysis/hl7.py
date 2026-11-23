import capstone, re
text=open(r"C:\ProgramData\scdump\69_7FF689681000.bin","rb").read()
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
spots=[0x23CE83C,0x23CE914,0x23CEA9C,0x23CEB39,0x23CEBD9,0x23CEC97,0x23CED25,0x23CEDFF,0x23CEEDF,0x23CEFDF,0x23CF11F,0x23CF2FF]
out=[]
for rva in spots:
    off=rva-0x1000
    ins=list(md.disasm(text[off:off+16], rva))
    if not ins: continue
    x=ins[0]
    m=re.search(r'rip \+ (0x[0-9a-f]+)', x.op_str)
    if m:
        tgt=x.address+x.size+int(m.group(1),16)
        out.append((rva,tgt))
        print("   RVA 0x%-8X ? ?? 0x%-9X  [%s %s]" % (rva,tgt,x.mnemonic,x.op_str))
    else:
        print("   RVA 0x%-8X  (? rip): %s %s" % (rva,x.mnemonic,x.op_str))
open("globs.txt","w").write("\n".join("%d"%t for _,t in out))
print("\n? %d ???" % len(out))
