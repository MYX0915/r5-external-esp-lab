import numpy as np, glob, os
targets=["E3FE5440","121D3840","15AF0CC0"]
for t in targets:
    fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%t) if os.path.getsize(p)>=0x4000]
    if not fs:
        print("  %s: no dump" % t); continue
    a=np.fromfile(fs[0],dtype=np.float32)
    n=len(a)//12
    m=a[:n*12].reshape(n,12)
    t3=m[:, [3,7,11]]
    ok=np.isfinite(t3).all(axis=1)
    mag=np.abs(t3).max(axis=1)
    ok &= (mag>1)&(mag<20000)
    # orthonormal-ish rows
    with np.errstate(over="ignore",invalid="ignore"):
        n0=np.linalg.norm(m[:,0:3],axis=1); n1=np.linalg.norm(m[:,4:7],axis=1); n2=np.linalg.norm(m[:,8:11],axis=1)
    orth=(np.abs(n0-1)<0.2)&(np.abs(n1-1)<0.2)&(np.abs(n2-1)<0.2)
    good=ok&orth
    idx=np.nonzero(good)[0]
    print("  %s: floats=%d  0x30-matrix-orthonormal hits=%d" % (t, len(a), len(idx)))
    if len(idx):
        print("     first at +0x%X  t=(%.1f,%.1f,%.1f)" % (idx[0]*0x30, *m[idx[0],[3,7,11]]))
        # consecutive runs
        runs=1; best=1
        for k in range(1,len(idx)):
            if idx[k]==idx[k-1]+1: runs+=1; best=max(best,runs)
            else: runs=1
        print("     longest consecutive run=%d" % best)
