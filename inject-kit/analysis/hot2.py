import numpy as np, glob, os, collections
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_12469B1C0.bin") if os.path.getsize(p)==0x4000], key=os.path.getmtime)
print("0x4000 dumps:", len(fs))
data=[np.fromfile(p,dtype=np.float32) for p in fs[-8:]]
n=min(len(d) for d in data)
cnt=collections.Counter()
for i in range(len(data)-1):
    a=data[i][:n]; b=data[i+1][:n]
    with np.errstate(invalid="ignore"):
        d=np.abs(a-b)
        m=np.isfinite(d)&(d>0.02)&(d<1000)
    for idx in np.nonzero(m)[0]: cnt[int(idx)]+=1
print("offsets changing EVERY interval with world-scale values:")
shown=0
for off,c in cnt.most_common(60):
    if c < len(data)-2: break
    vals=[float(data[k][off]) for k in range(len(data))]
    if not all(500 < abs(v) < 40000 for v in vals): continue
    print("  +0x%05X  %d/%d  %s" % (off*4, c, len(data)-1, ", ".join("%.1f"%v for v in vals[:4])))
    shown+=1
    if shown>=8: break
if shown==0: print("  (none)")
