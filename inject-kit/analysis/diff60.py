import numpy as np, glob, os
targets=["0x3AF1AAE0","0x4037C280"]
for a in targets:
    hexv=a[2:]
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x2000], key=os.path.getmtime)
    fs=fs[-60:]
    vals=[]
    for p in fs:
        d=np.fromfile(p,dtype=np.float32)
        nz=int((np.abs(d)>1e-6).sum())
        vals.append(nz)
    good=[i for i,v in enumerate(vals) if v>100]
    print("\n=== %s ===  ?%d???, ???? %d ?" % (a,len(fs),len(good)))
    if len(good)<3:
        print("   ???????????")
        continue
    M=np.stack([np.fromfile(fs[i],dtype=np.float32) for i in good])
    n=min(len(x) for x in M); M=M[:,:n]
    valid=np.isfinite(M).all(axis=0)&(np.abs(M)>1e-6).all(axis=0)
    ch=[]
    for off in np.nonzero(valid)[0]:
        col=M[:,off]
        rng=float(col.max()-col.min())
        if rng > 1e-3*max(1.0,abs(float(col.mean()))):
            ch.append((off,col))
    print("   ????: %d" % len(ch))
    for off,col in ch[:15]:
        print("      +0x%05X  %s" % (off*4, ", ".join("%.4g"%v for v in col[:10])))
