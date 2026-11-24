import numpy as np, glob, os
me=np.array((-7293.9, 1187.4, -20.0), dtype=np.float64)
for snap,base in ((2178,0x12C000000),(2179,0x12E000000)):
    fs=sorted(glob.glob(r"C:\ProgramData\scdump\%d_*.bin"%snap))
    if not fs: print("snap %d ???" % snap); continue
    p=fs[-1]
    a=np.fromfile(p, dtype=np.float32)
    n=len(a)//3*3
    T=a[:n].reshape(-1,3).astype(np.float64)
    with np.errstate(invalid="ignore",over="ignore"):
        d=np.linalg.norm(T-me, axis=1)
        m=np.isfinite(d)&(d<250)
    idx=np.nonzero(m)[0]
    print("%s (0x%X) %.1f MB ? 4.7m ??? %d" % (os.path.basename(p), base, os.path.getsize(p)/1048576, len(idx)))
    for i in idx[:8]:
        print("   0x%X  (%.2f,%.2f,%.2f)  %.2f m" % (base+int(i)*4, T[i][0],T[i][1],T[i][2], d[i]*0.01905))
