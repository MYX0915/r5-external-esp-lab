import numpy as np, glob, os, struct
l0=int(open("loot0.txt").read().strip(),16)
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
me=np.array(struct.unpack_from("<3f",f,32), dtype=np.float64)
print("loot=%s  me=(%.1f,%.1f,%.1f)" % (hex(l0), me[0],me[1],me[2]))
hexv="%X"%l0
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x1000], key=os.path.getmtime)
if not fs: print("? dump"); raise SystemExit
raw=open(fs[-1],"rb").read()
a=np.frombuffer(raw, dtype=np.float32)
n=len(a)//3*3
T=a[:n].reshape(-1,3).astype(np.float64)
with np.errstate(invalid="ignore",over="ignore"):
    inmap=(np.abs(T[:,0])<8000)&(np.abs(T[:,1])<8000)&(T[:,2]>-200)&(T[:,2]<2000)
    d=np.linalg.norm(T-me, axis=1)
    near=inmap&np.isfinite(d)&(d<2000)
idx=np.nonzero(near)[0]
print("\n????????????? <38??: %d ?" % len(idx))
for i in idx[:20]:
    print("  +0x%04X  (%.2f, %.2f, %.2f)  ? %.1f ?" % (int(i)*4, T[i][0],T[i][1],T[i][2], d[i]*0.01905))
print("\n????????????? 15??????:")
idx2=np.nonzero(inmap & np.isfinite(T).all(axis=1))[0]
for i in idx2[:15]:
    print("  +0x%04X  (%.1f, %.1f, %.1f)" % (int(i)*4, T[i][0],T[i][1],T[i][2]))
