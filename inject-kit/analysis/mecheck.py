import struct, glob, os, numpy as np
me=int(open("me.txt").read().strip(),16)
hexv="%X"%me
fs=sorted([x for x in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(x)==0x1000], key=os.path.getmtime)
if not fs: print("? dump??????"); raise SystemExit
raw=open(fs[-1],"rb").read()
print("???? dump ???? 32 ??:")
print("  " + " ".join("%02X"%b for b in raw[:32]))
a=np.frombuffer(raw, dtype=np.float32)
n=len(a)//3*3
T=a[:n].reshape(-1,3).astype(np.float64)
with np.errstate(invalid="ignore",over="ignore"):
    ok=np.isfinite(T).all(axis=1)&(np.abs(T)>100).all(axis=1)&(np.abs(T[:,0])<20000)&(np.abs(T[:,1])<20000)&(T[:,2]>-1000)&(T[:,2]<4000)
idx=np.nonzero(ok)[0]
print("\n???? %d ?:" % len(idx))
for i in idx[:8]:
    print("  +0x%04X (%.1f,%.1f,%.1f)" % (int(i)*4,T[i][0],T[i][1],T[i][2]))
