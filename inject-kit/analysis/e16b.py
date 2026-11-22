import struct, glob, os
res=[]
for line in open("ents16.txt"):
    va=line.split()[0]; hexv=va[2:]
    fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x2000]
    if not fs: continue
    raw=open(fs[0],"rb").read()
    vt=struct.unpack_from("<Q", raw, 0)[0]
    p170=struct.unpack_from("<Q", raw, 0x170)[0]
    pfd0=struct.unpack_from("<Q", raw, 0xFD0)[0]
    ok170 = 0x10000 < p170 < 0x7FFF00000000 and (p170 & 3)==0
    okfd0 = 0x10000 < pfd0 < 0x7FFF00000000 and (pfd0 & 7)==0
    res.append((hexv, vt, p170, ok170, pfd0, okfd0))
print("entity       vtable            +0x170               +0xFD0")
for hexv,vt,p170,ok170,pfd0,okfd0 in res:
    print("0x%-10s 0x%-14X 0x%-14X%-4s 0x%-12X%s" % (hexv, vt, p170, "PTR" if ok170 else "", pfd0, " PTR" if okfd0 else ""))
open("vecptr2.txt","w").write("\n".join("0x%X 0x10"%p170 for h,vt,p170,ok,_,_ in res if ok))
