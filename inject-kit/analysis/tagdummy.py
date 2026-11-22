import numpy as np, glob, os
for hexv in ("120127980","132729D90"):
    fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)>=0x4000]
    if not fs: print("%s: no dump"%hexv); continue
    raw=open(max(fs,key=os.path.getmtime),"rb").read()
    q=np.frombuffer(raw, dtype=np.uint64)
    tag=(q>>59)&0x1F
    low=(q & 0xFFFFFFFF).astype(np.uint32).view(np.float32)
    for t in (4,3,1,0):
        m=(tag==t)&np.isfinite(low)&(np.abs(low)<20000)&(np.abs(low)>1)
        n=int(m.sum())
        if n:
            print("%s tag=%d count=%d  e.g. %s" % (hexv,t,n,[ "%.1f"%low[i] for i in np.nonzero(m)[0][:5]]))
    print("%s: tag histogram %s" % (hexv, np.bincount(tag.astype(int), minlength=32).tolist()[:8]))
