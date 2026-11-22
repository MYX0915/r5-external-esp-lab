import numpy as np, glob, os
fs=[f for f in glob.glob(r"C:\ProgramData\scdump\4_*.bin") if os.path.getsize(f)>0x1000]
arrs=[np.fromfile(f,dtype=np.float32) for f in fs]
print("objects:", len(arrs))
n=min(len(a) for a in arrs)
score=np.zeros(n,dtype=np.int32)
for a in arrs:
    w=a[:n]
    ok=(np.isfinite(w)&(np.abs(w)>0.5)&(np.abs(w)<9000))
    score+=ok.astype(np.int32)
cand=np.argsort(-score)[:40]
shown=0
for i in cand:
    if score[i] < len(arrs)-1: break
    vals=[arrs[k][i] for k in range(len(arrs))]
    if len(set(np.round(vals,2))) < len(arrs)-2: continue
    print("  +0x%05X all-objects  %s" % (i*4, " ".join("%9.2f"%v for v in vals[:6])))
    shown+=1
    if shown>=10: break
print("shown:", shown)
