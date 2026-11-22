import numpy as np, glob, os
pos=np.array([float(x) for x in open("mepos.txt").read().split()])
res=[]
for line in open("candmap.txt"):
    off,va = line.split()
    hexva = va[2:]
    fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexva) if os.path.getsize(p)==0x10000]
    if not fs: continue
    a=np.fromfile(fs[0],dtype=np.float32)
    n=(len(a)//12)*12
    cnt=0; best=None
    for i in range(0, n-11, 12):
        m=a[i:i+12]
        if not np.isfinite(m).all(): continue
        t=np.array([m[3],m[7],m[11]])
        if np.abs(t).sum()<1: continue
        d=float(np.linalg.norm(t-pos))
        if best is None or d<best[0]: best=(d,i*4,t.copy())
        if d<400: cnt+=1
    res.append((cnt, off, va, best))
res.sort(reverse=True)
print("top objects by near-player matrix translations:")
for cnt,off,va,best in res[:8]:
    d,i,t = best
    print("   entity%s -> %-12s near-hits=%-4d nearest d=%8.1f at +0x%05X t=(%8.1f,%8.1f,%8.1f)" % (off,va,cnt,d,i,t[0],t[1],t[2]))
