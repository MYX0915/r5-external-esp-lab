import numpy as np, glob, os

def verdict(meta):
    try:
        for line in open(meta, errors="replace"):
            if line.startswith("#summary"):
                for t in line.split():
                    if t.startswith("verdict="): return t.split("=")[1]
    except Exception: pass
    return None

targets=[l.strip() for l in open("t4.txt") if l.strip()]
for a in targets:
    hexv=a[2:]
    fs=sorted(glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv), key=os.path.getmtime)[-25:]
    good=[]
    for p in fs:
        m=p+".meta"
        v=verdict(m) if os.path.exists(m) else None
        if v=="COMPLETE": good.append(p)
    print("\n=== %s ===  ?? %d, COMPLETE %d" % (a,len(fs),len(good)))
    if len(good)<4:
        print("   ??????"); continue
    M=np.stack([np.fromfile(p,dtype=np.float32) for p in good])
    n=min(len(x) for x in M); M=M[:,:n]
    # ???????????????????
    fin=np.isfinite(M).all(axis=0)
    ch=[]
    for off in np.nonzero(fin)[0]:
        col=M[:,off]
        rng=float(col.max()-col.min())
        scale=max(1.0, abs(float(col.mean())))
        if rng > 1e-3*scale:
            ch.append((off,col))
    print("   ????: %d" % len(ch))
    for off,col in ch[:12]:
        print("      +0x%05X  %s" % (off*4, ", ".join("%.4g"%v for v in col[:12])))
