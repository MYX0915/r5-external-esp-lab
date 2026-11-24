import numpy as np, glob, os
def verdict(meta):
    try:
        for line in open(meta, errors="replace"):
            if line.startswith("#summary"):
                for t in line.split():
                    if t.startswith("verdict="): return t.split("=")[1]
    except Exception: pass
    return None
for a in ("0x299FB1C0","0x112A1B270"):
    hexv=a[2:]
    fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x8000]
    fs.sort(key=os.path.getmtime); fs=fs[-15:]
    good=[p for p in fs if os.path.exists(p+".meta") and verdict(p+".meta")=="COMPLETE"]
    print("\n=== %s === ?? %d, COMPLETE %d" % (a,len(fs),len(good)))
    if len(good)<4: print("   ????"); continue
    M=np.stack([np.fromfile(p,dtype=np.float32) for p in good])
    n=min(len(x) for x in M); M=M[:,:n]
    fin=np.isfinite(M).all(axis=0)
    ch=[]
    for off in np.nonzero(fin)[0]:
        col=M[:,off]
        rng=float(col.max()-col.min())
        if rng > 1e-3*max(1.0,abs(float(col.mean()))): ch.append((off,col))
    # ??? tick ????tick ? 1000~100000 ???????
    print("   ???? %d ??? tick ???:" % len(ch))
    shown=0
    for off,col in ch:
        v=col.astype(float)
        mono=bool(np.all(np.diff(v)>=0)) and float(v[-1])>1000
        if mono: continue
        print("      +0x%05X  %s" % (off*4, ", ".join("%.4g"%x for x in col[:12])))
        shown+=1
        if shown>=14: break
    if shown==0: print("      ???")
