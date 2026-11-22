import numpy as np, glob, os
insts=[l.strip() for l in open("d24.txt") if l.strip()]
print("scanning for changed slots with WORLD-scale values...")
for v in insts:
    hexv=v[2:]
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x4000], key=os.path.getmtime)
    if len(fs)<2: continue
    a=np.fromfile(fs[-2],dtype=np.float32); b=np.fromfile(fs[-1],dtype=np.float32)
    n=min(len(a),len(b))
    with np.errstate(invalid="ignore"):
        d=np.abs(a[:n]-b[:n])
        big=(np.abs(a[:n])>800)&(np.abs(b[:n])>800)&np.isfinite(d)&(d>0.05)
    idx=np.nonzero(big)[0]
    if len(idx):
        print("  %s changed world-scale slots=%d" % (v,len(idx)))
        for i in idx[:6]:
            print("      +0x%05X  %.2f -> %.2f" % (i*4, a[i], b[i]))
