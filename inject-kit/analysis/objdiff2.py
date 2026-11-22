import numpy as np, glob, os
insts=[l.strip() for l in open("d24.txt") if l.strip()]
print("checking %d entities" % len(insts))
res=[]
for v in insts:
    hexv=v[2:]
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x4000], key=os.path.getmtime)
    if len(fs)<2: continue
    a=np.fromfile(fs[-2],dtype=np.float32); b=np.fromfile(fs[-1],dtype=np.float32)
    n=min(len(a),len(b)); d=np.abs(a[:n]-b[:n])
    with np.errstate(invalid="ignore"):
        m=np.isfinite(d)&(d>0.15)&(d<5000)
    idx=np.nonzero(m)[0]
    if len(idx):
        res.append((len(idx), v, a, b, idx))
res.sort(reverse=True)
print("entities with changing data: %d" % len(res))
for c,v,a,b,idx in res[:6]:
    print("  %s changed=%d" % (v,c))
    for i in idx[:6]:
        print("      +0x%05X  %.3f -> %.3f" % (i*4, a[i], b[i]))
