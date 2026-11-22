import numpy as np, struct, bisect, capstone
text=open(r"C:\ProgramData\scdump\2_7FF776981000.bin","rb").read()
pdata=open(r"C:\ProgramData\scdump\8_7FF784870000.bin","rb").read()
n=len(pdata)//12
ents=[]
for i in range(n):
    b,e,u=struct.unpack_from("<III",pdata,i*12)
    if b: ents.append((b,e))
ents.sort(); begins=[e[0] for e in ents]
def func_of(rva):
    i=bisect.bisect_right(begins, rva)-1
    if i>=0 and ents[i][0] <= rva < ents[i][1]: return ents[i]
    return None
# find all refs to 0x1F78 and 0x1F84
refs={}
for name,disp in (("cam",bytes.fromhex("781F0000")), ("ang",bytes.fromhex("841F0000"))):
    i=0
    while True:
        i=text.find(disp,i)
        if i<0: break
        f=func_of(i)
        if f: refs.setdefault(f[0], set()).add(name)
        i+=1
print("functions referencing camera/angle fields:", len(refs))
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
for start, kinds in list(refs.items())[:10]:
    end=None
    for b,e in ents:
        if b==start: end=e; break
    size=(end-start) if end else 0
    # count loop-ish instructions & memory writes in first part
    ins=list(md.disasm(text[start:min(end or start+0x400, start+0x400)], start))
    jmp_back=sum(1 for x in ins if x.mnemonic.startswith('j') )
    print("  func 0x%-8X size=%-6d kinds=%-8s insns=%d branches=%d" % (start, size, ",".join(sorted(kinds)), len(ins), jmp_back))
