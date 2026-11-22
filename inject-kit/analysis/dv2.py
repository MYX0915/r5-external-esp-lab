import numpy as np, glob, os
fs=[f for f in glob.glob(r"C:\ProgramData\scdump\9_*.bin") if os.path.getsize(f)>0x1000]
print("dumped:", len(fs))
arrs=[np.fromfile(f,dtype=np.float32) for f in fs]
n=min(len(a) for a in arrs)
score=np.zeros(n,dtype=np.int32)
for a in arrs:
    w=a[:n]
    score += (np.isfinite(w)&(np.abs(w)>0.5)&(np.abs(w)<9000)).astype(np.int32)
for i in np.argsort(-score)[:6]:
    if score[i] < len(arrs)-1: break
    vals=[arrs[k][i] for k in range(len(arrs))]
    print("  +0x%05X  %s" % (i*4, " ".join("%9.2f"%v for v in vals)))
