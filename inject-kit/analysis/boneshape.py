import numpy as np, glob, os
def runs(a, stride=0x30, need=25, cluster=250.0):
    n=(len(a)*4)//stride
    best=None; cur=[]
    for i in range(n):
        m=a[i*12:(i+1)*12]
        if len(m)<12 or not np.isfinite(m).all(): cur=[]; continue
        t=np.array([m[3],m[7],m[11]])
        if np.abs(t).max()>20000 or np.abs(t).max()<1: cur=[]; continue
        if cur and float(np.linalg.norm(t-cur[-1][1]))<cluster: cur.append((i,t))
        else: cur=[(i,t)]
        if len(cur)>=need and (best is None or len(cur)>len(best)): best=list(cur)
    return best
res=[]
for line in open("candmap.txt"):
    off,va = line.split()
    hexva=va[2:]
    fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexva) if os.path.getsize(p)==0x10000]
    if not fs: continue
    a=np.fromfile(fs[0],dtype=np.float32)
    r=runs(a)
    if r: res.append((len(r), off, va, r[0][0]*0x30, r[0][1].copy(), r[-1][1].copy()))
res.sort(reverse=True)
print("objects with a bone-like matrix run:", len(res))
for ln,off,va,st,t0,t1 in res[:8]:
    print("   entity%s -> %-11s run=%-4d at +0x%05X  from (%9.1f,%9.1f,%9.1f) to (%9.1f,%9.1f,%9.1f)" %
          (off,va,ln,st,t0[0],t0[1],t0[2],t1[0],t1[1],t1[2]))
