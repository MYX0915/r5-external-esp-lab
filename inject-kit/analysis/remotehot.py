import numpy as np, glob, os, collections
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_11FEB5B30.bin") if os.path.getsize(p)==0x8000], key=os.path.getmtime)
print("dumps:", len(fs))
data=[np.fromfile(p,dtype=np.float32) for p in fs[-6:]]
n=min(len(d) for d in data)
cnt=collections.Counter()
for i in range(len(data)-1):
    a=data[i][:n]; b=data[i+1][:n]
    with np.errstate(invalid="ignore"):
        d=np.abs(a-b)
        m=np.isfinite(d)&(d>0.05)&(d<5000)
    for idx in np.nonzero(m)[0]: cnt[int(idx)]+=1
print("????????")
shown=0
for off,c in cnt.most_common(40):
    vals=[float(data[k][off]) for k in range(len(data))]
    if not all(np.isfinite(vals)): continue
    rng=max(vals)-min(vals)
    print("  +0x%05X ?%d?  ?: %s" % (off*4,c,", ".join("%.1f"%v for v in vals[:4])))
    shown+=1
    if shown>=12: break
