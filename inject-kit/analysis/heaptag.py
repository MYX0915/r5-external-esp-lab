import numpy as np, glob, os, struct
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
pos=np.array(struct.unpack_from("<3f",f,32))
print("player pos:", ["%.1f"%v for v in pos])
fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_h*.bin") if os.path.getsize(p)>0x100000]
fs.sort(key=os.path.getmtime, reverse=True)
print("recent heap files:", len(fs))
best=[]
for f2 in fs[:30]:
    a=np.fromfile(f2, dtype=np.uint64)
    tag=(a>>59)&0x1F
    low=(a & 0xFFFFFFFF).astype(np.uint32).view(np.float32)
    m=(tag==4)&np.isfinite(low)&(np.abs(low)<20000)&(np.abs(low)>1)
    n=int(m.sum())
    if n>0:
        best.append((n, os.path.basename(f2), np.nonzero(m)[0][:5].tolist(), low[m][:5].tolist()))
best.sort(reverse=True)
print("files containing tag==4 float-like values:", len(best))
for n,nm,idx,vals in best[:6]:
    print("   %-24s count=%-5d e.g. offs=%s vals=%s" % (nm,n,[hex(int(i*8)) for i in idx],["%.1f"%v for v in vals]))
