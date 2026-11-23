import numpy as np, glob, os, collections
addrs=[l.strip() for l in open("near.txt") if l.strip()]
print("?? %d ?????????? 6 ? 0x2000 dump" % len(addrs))
for a in addrs:
    hexv=a[2:]
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x2000], key=os.path.getmtime)[-6:]
    if len(fs)<3: print("  %s: dump ??" % a); continue
    data=[np.fromfile(p,dtype=np.float32) for p in fs]
    n=min(len(d) for d in data)
    cnt=collections.Counter()
    for i in range(len(data)-1):
        A=data[i][:n]; B=data[i+1][:n]
        with np.errstate(invalid="ignore"):
            d=np.abs(A-B)
            m=np.isfinite(d)&(d>0.001)&(d<1e6)
        for idx in np.nonzero(m)[0]: cnt[int(idx)]+=1
    if cnt:
        print("\n  0x%s  ????:" % a[2:])
        for off,c in cnt.most_common(10):
            vals=["%.4g"%data[k][off] for k in range(len(data))]
            print("     +0x%05X ?%d?  %s" % (off*4,c,", ".join(vals)))
    else:
        print("  0x%s  ???" % a[2:])
