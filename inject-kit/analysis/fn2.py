import struct, bisect, capstone
text=open(r"C:\ProgramData\scdump\2_7FF776981000.bin","rb").read()
pdata=open(r"C:\ProgramData\scdump\8_7FF784870000.bin","rb").read()
n=len(pdata)//12
sizes={}
for i in range(n):
    b,e,u=struct.unpack_from("<III",pdata,i*12)
    if b and e>b: sizes[b]=e
begins=sorted(sizes)
def func_of(rva):
    i=bisect.bisect_right(begins, rva)-1
    if i<0: return None
    s=begins[i]
    if s <= rva < sizes[s]: return s
    return None
refs={}
for name,disp in (("cam",bytes.fromhex("781F0000")), ("ang",bytes.fromhex("841F0000"))):
    i=0
    while True:
        i=text.find(disp,i)
        if i<0: break
        s=func_of(i)
        if s is not None: refs.setdefault(s,set()).add(name)
        i+=1
print("functions:", len(refs))
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
rows=[]
for s,kinds in refs.items():
    e=sizes[s]; size=e-s
    ins=list(md.disasm(text[s:min(e, s+0x600)], s))
    br=sum(1 for x in ins if x.mnemonic.startswith("j"))
    writes=sum(1 for x in ins if "movss" in x.mnemonic or "movaps" in x.mnemonic or "movups" in x.mnemonic)
    rows.append((br, size, s, ",".join(sorted(kinds)), len(ins), writes))
rows.sort(reverse=True)
for br,size,s,kinds,nins,w in rows[:10]:
    print("  func 0x%-8X size=%-6d %-8s insns=%-4d branches=%-3d vecWrites=%d" % (s,size,kinds,nins,br,w))
