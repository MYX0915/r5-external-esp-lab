import numpy as np, glob, os, struct
l0=int(open("loot0.txt").read().strip(),16)
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
me=np.array(struct.unpack_from("<3f",f,32), dtype=np.float64)
hexv="%X"%l0
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x4000], key=os.path.getmtime)
if not fs: print("? 0x4000 dump"); raise SystemExit
raw=open(fs[-1],"rb").read()
a=np.frombuffer(raw, dtype=np.float32)
n=len(a)//3*3
T=a[:n].reshape(-1,3).astype(np.float64)
with np.errstate(invalid="ignore",over="ignore"):
    finite=np.isfinite(T).all(axis=1)
    big=(np.abs(T) > 100.0).all(axis=1)
    inmap=(np.abs(T[:,0])<20000)&(np.abs(T[:,1])<20000)&(T[:,2]>-500)&(T[:,2]<3000)
    d=np.linalg.norm(T-me, axis=1)
    ok=finite&big&inmap
idx=np.nonzero(ok)[0]
print("loot=%s me=(%.0f,%.0f,%.0f)" % (hex(l0),me[0],me[1],me[2]))
print("????????>100 ???????: %d" % len(idx))
res=sorted([(d[i],i) for i in idx])
for dd,i in res[:15]:
    print("  +0x%04X  (%.1f, %.1f, %.1f)  ? %.1f ?" % (int(i)*4, T[i][0],T[i][1],T[i][2], dd*0.01905))
