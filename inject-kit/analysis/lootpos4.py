import numpy as np, glob, os, struct
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
me=np.array(struct.unpack_from("<3f",f,32), dtype=np.float64)
print("me=(%.0f,%.0f,%.0f)\n" % (me[0],me[1],me[2]))
for l in [x.strip() for x in open("loots5.txt") if x.strip()]:
    e=int(l,16); hexv="%X"%e
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x4000], key=os.path.getmtime)
    if not fs: print("%s ?dump" % l); continue
    a=np.frombuffer(open(fs[-1],"rb").read(), dtype=np.float32)
    n=len(a)//3*3
    T=a[:n].reshape(-1,3).astype(np.float64)
    with np.errstate(invalid="ignore",over="ignore"):
        ok=np.isfinite(T).all(axis=1)&(np.abs(T)>100).all(axis=1)&(np.abs(T[:,0])<20000)&(np.abs(T[:,1])<20000)&(T[:,2]>-500)&(T[:,2]<3000)
        d=np.linalg.norm(T-me, axis=1)
    idx=np.nonzero(ok)[0]
    best=""
    if len(idx):
        i=idx[np.argmin(d[idx])]
        best="???? +0x%04X (%.1f,%.1f,%.1f) ?%.0f?" % (int(i)*4,T[i][0],T[i][1],T[i][2],d[i]*0.01905)
    print("  %s  ??%d  %s" % (l, len(idx), best))
