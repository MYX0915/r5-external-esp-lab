import numpy as np, glob, os
fs=[f for f in glob.glob(r"C:\ProgramData\scdump\18_*.bin") if os.path.getsize(f)>0x1000]
print("valid dumps:", len(fs))
arrs=[np.fromfile(f,dtype=np.float32) for f in fs]
n=min(len(a) for a in arrs)
score=np.zeros(n,dtype=np.int32)
for a in arrs:
    w=a[:n]
    ok=np.zeros(n,dtype=bool)
    x,y,z=w[:-2],w[1:-1],w[2:]
    ok[:-2]=(np.isfinite(x)&np.isfinite(y)&np.isfinite(z)&
             (np.abs(x)<9000)&(np.abs(y)<9000)&(z>-500)&(z<2000)&
             ((np.abs(x)>10)|(np.abs(y)>10)))
    score+=ok.astype(np.int32)
best=np.argsort(-score)[:10]
for i in best:
    if score[i]<5: break
    print("  +0x%05X  %d/%d objects" % (i*4, score[i], len(arrs)))
    for a in arrs[:3]:
        v=a[i:i+3]
        print("        (%9.2f,%9.2f,%9.2f)" % (v[0],v[1],v[2]))
