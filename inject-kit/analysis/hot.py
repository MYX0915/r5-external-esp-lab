import numpy as np, glob, os, collections
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_12469B1C0.bin") if os.path.getsize(p)==0x1000], key=os.path.getmtime)
print("dumps:", len(fs))
data=[np.fromfile(p,dtype=np.float32) for p in fs]
n=min(len(d) for d in data)
cnt=collections.Counter()
for i in range(len(data)-1):
    a=data[i][:n]; b=data[i+1][:n]
    with np.errstate(invalid="ignore"):
        d=np.abs(a-b)
        m=np.isfinite(d)&(d>0.02)&(d<20000)
    for idx in np.nonzero(m)[0]: cnt[int(idx)]+=1
print("offsets changing in most intervals:")
for off,c in cnt.most_common(12):
    vals=[float(data[k][off]) for k in range(len(data))]
    print("  +0x%05X  changed %d/%d times   values: %s" % (off*4, c, len(data)-1,
          ", ".join("%.1f"%v for v in vals[:5])))
