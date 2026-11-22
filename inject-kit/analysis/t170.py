import numpy as np, glob, os, struct
for line in open("memap.txt"):
    pass
cands=["35D43570"]
for line in open("memap.txt"):
    parts=line.split()
    if len(parts)==2: cands.append(parts[1][2:])
seen=[]
for c in cands:
    fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%c) if os.path.getsize(p)==0x2000]
    if not fs: continue
    raw=open(fs[0],"rb").read()
    p170=struct.unpack_from("<Q", raw, 0x170)[0]
    pfd0=struct.unpack_from("<Q", raw, 0xFD0)[0]
    ok170 = 0x10000 < p170 < 0x7FFF00000000 and (p170 & 3)==0
    okfd0 = 0x10000 < pfd0 < 0x7FFF00000000 and (pfd0 & 7)==0
    print("  0x%-10s +0x170=0x%-14X %s  +0xFD0=0x%-14X %s" % (c,p170,"PTR" if ok170 else "   ",pfd0,"PTR" if okfd0 else "   "))
    if ok170: seen.append(p170)
    if len(seen)>=3: break
open("vecptrs.txt","w").write("\n".join("0x%X 0x10"%v for v in seen))
print("vector pointers to test:", len(seen))
