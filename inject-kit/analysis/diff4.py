import numpy as np, glob, os, collections
targets=[l.strip() for l in open("targets4.txt") if l.strip()]
for a in targets:
    hexv=a[2:]
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x2000], key=lambda x: os.path.getmtime(x))[-15:]
    if len(fs)<4: print("%s: dump %d ????" % (a,len(fs))); continue
    data=[np.fromfile(p,dtype=np.float32) for p in fs]
    n=min(len(d) for d in data)
    M=np.stack([d[:n] for d in data])
    # ????????????????????????
    valid=np.isfinite(M).all(axis=0)&(np.abs(M)>1e-6).all(axis=0)
    changes=[]
    for off in np.nonzero(valid)[0]:
        col=M[:,off]
        if col.max()-col.min() > 1e-4*max(1.0,abs(float(col.mean()))):
            changes.append((off, col))
    print("\n=== %s ===" % a)
    if not changes:
        print("   ??????")
        continue
    for off,col in changes[:12]:
        vals=", ".join("%.4g"%v for v in col)
        print("   +0x%05X  %s" % (off*4, vals[:120]))
