import struct, bisect, capstone
text=open(r"C:\ProgramData\scdump\2_7FF776981000.bin","rb").read()
pdata=open(r"C:\ProgramData\scdump\8_7FF784870000.bin","rb").read()
sizes={}
for i in range(4, len(pdata)-12, 12):
    b,e,u=struct.unpack_from("<III",pdata,i)
    if 0x1000 <= b < e <= 0x2CA2B7C and (e-b) < 0x20000:
        sizes.setdefault(b,e)
print("valid functions:", len(sizes))
begins=sorted(sizes)
def func_of(rva):
    i=bisect.bisect_right(begins, rva)-1
    if i<0: return None
    s=begins[i]
    return s if rva < sizes[s] else None
refs={}
for name,disp in (("cam",bytes.fromhex("781F0000")), ("ang",bytes.fromhex("841F0000"))):
    i=0
    while True:
        i=text.find(disp,i)
        if i<0: break
        s=func_of(i)
        if s is not None: refs.setdefault(s,set()).add(name)
        i+=1
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
rows=[]
for s,kinds in refs.items():
    e=sizes[s]; ins=list(md.disasm(text[s:min(e,s+0xA00)], s))
    br=sum(1 for x in ins if x.mnemonic.startswith("j"))
    vw=sum(1 for x in ins if any(k in x.mnemonic for k in ("movss","movaps","movups","movdqu","mulps","addps")))
    rows.append((vw,br,s,e-s,",".join(sorted(kinds))))
rows.sort(reverse=True)
print("functions referencing cam/ang:", len(rows))
for vw,br,s,size,kinds in rows[:8]:
    print("  func 0x%-8X size=%-6d %-8s vecOps=%-3d branches=%d" % (s,size,kinds,vw,br))
