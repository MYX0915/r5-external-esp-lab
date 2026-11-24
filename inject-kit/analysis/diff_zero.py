import numpy as np, glob, os
targets=["0x3AF1AAE0","0x4037C280"]
for a in targets:
    hexv=a[2:]
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x2000], key=os.path.getmtime)[-60:]
    rows=[]
    for p in fs:
        d=np.fromfile(p,dtype=np.float32)
        nz=int((np.abs(d)>1e-6).sum())
        if nz>100: rows.append(d)
    if len(rows)<4: print(a,"????"); continue
    M=np.stack(rows); n=min(len(x) for x in M); M=M[:,:n]
    zero=(M==0)
    n_zero=zero.sum(axis=0); n_tot=len(rows)
    # ? 0 ???? ? ????? 0
    trigger=[o for o in range(n) if 0 < n_zero[o] < n_tot]
    print("\n=== %s === ???? %d, ??0/???????: %d" % (a,len(rows),len(trigger)))
    for o in trigger[:25]:
        col=M[:,o]
        vals=" ".join(("%.3g"%v) for v in col)
        print("   +0x%05X  [%s]" % (o*4, vals[:150]))
