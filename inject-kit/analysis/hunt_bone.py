import numpy as np, glob, os
pos=np.array([float(x) for x in open("mepos.txt").read().split()])
print("player pos:", ["%.1f"%v for v in pos])
hits=[]
for line in open("candmap.txt"):
    off,va = line.split()
    hexva = va[2:]
    fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexva) if os.path.getsize(p)==0x2000]
    if not fs: continue
    a=np.fromfile(fs[0],dtype=np.float32)
    n=(len(a)//12)*12
    for i in range(0, n-11, 12):
        m=a[i:i+12]
        if not np.isfinite(m).all(): continue
        t=np.array([m[3],m[7],m[11]])
        if np.abs(t).sum()<1: continue
        d=float(np.linalg.norm(t-pos))
        if d < 300:
            with np.errstate(over="ignore",invalid="ignore"):
                ok=all(0.5<np.linalg.norm(m[k:k+3])<1.5 for k in (0,4,8))
            if ok: hits.append((off, va, i*4, t.copy(), d))
print("bone-matrix candidates:", len(hits))
for off,va,boff,t,d in hits[:10]:
    print("   entity%s -> %s  bone+0x%05X t=(%9.1f,%9.1f,%9.1f) d=%.1f" % (off,va,boff,t[0],t[1],t[2],d))
