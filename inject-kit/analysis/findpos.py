import struct, glob, os, numpy as np, math
p=0x1A4B1D380
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
me=np.array(struct.unpack_from("<3f",f,32), dtype=np.float64)
hexv="%X"%p
fs=sorted([x for x in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(x)==0x6000], key=os.path.getmtime)
if not fs: print("?dump"); raise SystemExit
raw=open(fs[-1],"rb").read()
a=np.frombuffer(raw, dtype=np.float32)
n=len(a)//3*3
T=a[:n].reshape(-1,3).astype(np.float64)
with np.errstate(invalid="ignore",over="ignore"):
    ok=np.isfinite(T).all(axis=1)&(np.abs(T)>100).all(axis=1)&(np.abs(T[:,0])<20000)&(np.abs(T[:,1])<20000)&(T[:,2]>-1000)&(T[:,2]<4000)
    d=np.linalg.norm(T-me,axis=1)
idx=np.nonzero(ok)[0]
print("???? 0x%X  ???????: %d" % (p,len(idx)))
print("??????: (%.1f,%.1f,%.1f)\n" % (me[0],me[1],me[2]))
res=sorted([(d[i],i) for i in idx])
for dd,i in res[:12]:
    print("  +0x%05X  (%.1f, %.1f, %.1f)   ????? %.1f ?" % (int(i)*4, T[i][0],T[i][1],T[i][2], dd*0.01905))
