import struct, glob, os, numpy as np
p=0x1A4B1D380
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
me=np.array(struct.unpack_from("<3f",f,32), dtype=np.float64)
print("??????: (%.1f,%.1f,%.1f)\n" % (me[0],me[1],me[2]))
found=0
for off in (0x0,0x1000,0x2000,0x3000,0x4000):
    va=p+off; hexv="%X"%va
    fs=sorted([x for x in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(x)==0x1000], key=os.path.getmtime)
    if not fs: continue
    raw=open(fs[-1],"rb").read()
    a=np.frombuffer(raw, dtype=np.float32)
    n=len(a)//3*3
    T=a[:n].reshape(-1,3).astype(np.float64)
    with np.errstate(invalid="ignore",over="ignore"):
        ok=np.isfinite(T).all(axis=1)&(np.abs(T)>100).all(axis=1)&(np.abs(T[:,0])<20000)&(np.abs(T[:,1])<20000)&(T[:,2]>-1000)&(T[:,2]<4000)
        d=np.linalg.norm(T-me,axis=1)
    idx=np.nonzero(ok)[0]
    for i in sorted(idx, key=lambda i: d[i])[:6]:
        print("  +0x%05X  (%.1f, %.1f, %.1f)  ??? %.1f ?" % (off+int(i)*4, T[i][0],T[i][1],T[i][2], d[i]*0.01905))
        found+=1
print("\n? %d ???" % found)
