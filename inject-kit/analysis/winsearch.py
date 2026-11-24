import numpy as np, glob, os
me=np.array((-7293.9, 1187.4, -20.0), dtype=np.float64)
fs=sorted(glob.glob(r"C:\ProgramData\scdump\2177_12D000000.bin"))
if not fs:
    fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_12D000000.bin")]
print("??: %s  ?? %.1f MB" % (os.path.basename(fs[-1]), os.path.getsize(fs[-1])/1048576))
a=np.fromfile(fs[-1], dtype=np.float32)
n=len(a)//3*3
T=a[:n].reshape(-1,3).astype(np.float64)
with np.errstate(invalid="ignore",over="ignore"):
    d=np.linalg.norm(T-me, axis=1)
    m=np.isfinite(d)&(d<250)
idx=np.nonzero(m)[0]
print("??? <4.7m ??????: %d ?" % len(idx))
for i in idx[:20]:
    print("   0x%X  (%.2f, %.2f, %.2f)  ? %.2f m" % (
        0x12D000000+int(i)*4, T[i][0], T[i][1], T[i][2], d[i]*0.01905))
