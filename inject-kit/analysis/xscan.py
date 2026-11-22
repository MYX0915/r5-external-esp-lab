import numpy as np, glob, os
fs=[f for f in glob.glob(r"C:\ProgramData\scdump\vd*.bin") if os.path.getsize(f)>=0x2000]
arrs=[np.fromfile(f,dtype=np.float32) for f in fs]
print("objects:", len(arrs))
n=min(len(a) for a in arrs)
best=[]
for i in range(0, n-3):
    vals=[a[i] for a in arrs]
    fin=[v for v in vals if np.isfinite(v)]
    if len(fin) < len(arrs)-1: continue
    if max(abs(v) for v in fin) > 12000: continue
    nz=sum(1 for v in fin if abs(v)>0.5)
    if nz < len(arrs)-2: continue
    distinct=len(set(round(v,1) for v in fin))
    if distinct < 6: continue
    best.append((distinct, i*4, fin))
best.sort(reverse=True)
print("candidate offsets (value differs across instances):", len(best))
for distinct, off, vals in best[:6]:
    print("  +0x%05X distinct=%d  %s" % (off, distinct, " ".join("%8.1f"%v for v in vals[:6])))
