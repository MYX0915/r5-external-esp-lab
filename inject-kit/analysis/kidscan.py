import struct, glob, os, numpy as np
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
me=np.array(struct.unpack_from("<3f",f,32), dtype=np.float64)
print("me=(%.1f,%.1f,%.1f)\n" % (me[0],me[1],me[2]))
kids=[l.strip() for l in open("kids.txt") if l.strip()]
for k in kids:
    e=int(k,16); hexv="%X"%e
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x200], key=os.path.getmtime)
    if not fs: print("  %s ?dump" % k); continue
    a=np.frombuffer(open(fs[-1],"rb").read(), dtype=np.float32)
    n=len(a)//3*3
    T=a[:n].reshape(-1,3).astype(np.float64)
    with np.errstate(invalid="ignore",over="ignore"):
        ok=np.isfinite(T).all(axis=1)&(np.abs(T)>50).any(axis=1)&(np.abs(T[:,0])<20000)&(np.abs(T[:,1])<20000)&(T[:,2]>-500)&(T[:,2]<3000)
        d=np.linalg.norm(T-me, axis=1)
    idx=np.nonzero(ok)[0]
    if len(idx)==0:
        print("  %-14s ???" % k); continue
    best=sorted([(d[i],i) for i in idx])[:2]
    s="; ".join("+0x%X (%.1f,%.1f,%.1f) %.1fm" % (int(i)*4,T[i][0],T[i][1],T[i][2],dd*0.01905) for dd,i in best)
    print("  %-14s ??%-2d  %s" % (k, len(idx), s))
