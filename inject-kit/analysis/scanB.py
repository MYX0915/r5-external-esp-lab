import struct, glob, os, numpy as np
b=0x1293AE950
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
pos=np.array(struct.unpack_from("<3f",f,32), dtype=np.float64)
print("??: (%.1f,%.1f,%.1f)\n" % (pos[0],pos[1],pos[2]))
print("??B 0x%X ?????:" % b)
hits=[]
for off in range(0,0x8000,0x1000):
    va=b+off; hexv="%X"%va
    fs=sorted([x for x in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(x)==0x1000], key=os.path.getmtime)
    if not fs: continue
    raw=open(fs[-1],"rb").read()
    a=np.frombuffer(raw, dtype=np.float32)
    n=len(a)//3*3
    T=a[:n].reshape(-1,3).astype(np.float64)
    with np.errstate(invalid="ignore",over="ignore"):
        ok=np.isfinite(T).all(axis=1)&(np.abs(T)>200).all(axis=1)&(np.abs(T[:,0])<20000)&(np.abs(T[:,1])<20000)&(T[:,2]>-800)&(T[:,2]<3000)
    for i in np.nonzero(ok)[0]:
        hits.append((off+int(i)*4, T[i]))
print("?? %d ?:" % len(hits))
for off,t in hits[:15]:
    d=float(np.linalg.norm(t-pos))*0.01905
    print("  +0x%05X  (%.1f, %.1f, %.1f)  ??? %.1f ?" % (off,t[0],t[1],t[2],d))
