import numpy as np, glob, os
pos=np.array([float(x) for x in open("mepos.txt").read().split()])
hits=[]
for line in open("candmap.txt"):
    off,va = line.split()
    hexva = va[2:]
    fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexva) if os.path.getsize(p)==0x10000]
    if not fs: continue
    a=np.fromfile(fs[0],dtype=np.float32)
    n=(len(a)//12)*12
    cnt=0
    for i in range(0, n-11, 12):
        m=a[i:i+12]
        if not np.isfinite(m).all(): continue
        t=np.array([m[3],m[7],m[11]])
        if np.abs(t).sum()<1: continue
        if float(np.linalg.norm(t-pos)) > 400: continue
        with np.errstate(over="ignore",invalid="ignore"):
            if not all(0.5<np.linalg.norm(m[k:k+3])<1.5 for k in (0,4,8)): continue
        cnt+=1
        if cnt==1: hits.append((off,va,i*4,t.copy()))
    if cnt>3:
        print("   %s -> %s : %d matrix-like entries near player" % (off,va,cnt))
print("objects with hits:", len(hits))
for off,va,boff,t in hits[:8]:
    print("   entity%s -> %s bone+0x%05X t=(%9.1f,%9.1f,%9.1f)" % (off,va,boff,t[0],t[1],t[2]))
