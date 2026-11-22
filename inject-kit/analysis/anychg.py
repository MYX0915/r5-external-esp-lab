import numpy as np, glob, os
insts=[l.strip() for l in open("all869.txt") if l.strip()]
changed=0; total=0; samples=[]
for v in insts:
    hexv=v[2:]
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x4000], key=os.path.getmtime)
    if len(fs)<2: continue
    total+=1
    a=np.fromfile(fs[-2],dtype=np.float32); b=np.fromfile(fs[-1],dtype=np.float32)
    n=min(len(a),len(b))
    with np.errstate(invalid="ignore"):
        d=np.abs(a[:n]-b[:n])
        m=np.isfinite(d)&(d>0.2)&(d<1e6)
    c=int(m.sum())
    if c:
        changed+=1
        if len(samples)<5:
            idx=np.nonzero(m)[0][:3]
            samples.append((v,c,[(hex(int(i*4)),float(a[i]),float(b[i])) for i in idx]))
print("entities compared=%d  with ANY float change=%d" % (total,changed))
for v,c,s in samples:
    print("  %s c=%d %s" % (v,c,s))
# verify file freshness
fs=sorted(glob.glob(r"C:\ProgramData\scdump\1[0-9]*_*.bin"), key=os.path.getmtime)[-4:]
print("newest dump files:")
for p in fs: print("   %s  %s" % (os.path.basename(p), os.path.getsize(p)))
