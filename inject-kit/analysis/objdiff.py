import numpy as np, glob, os
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_120127980.bin") if os.path.getsize(p)==0x20000], key=os.path.getmtime)
print("dumps:", [os.path.basename(x) for x in fs])
if len(fs)>=2:
    a=np.fromfile(fs[-2],dtype=np.float32); b=np.fromfile(fs[-1],dtype=np.float32)
    n=min(len(a),len(b))
    d=np.abs(a[:n]-b[:n])
    with np.errstate(invalid="ignore"):
        m=np.isfinite(d)&(d>0.2)&(d<5000)
    idx=np.nonzero(m)[0]
    print("changed float slots: %d" % len(idx))
    for i in idx[:20]:
        print("   +0x%06X  %.3f -> %.3f   (delta %.3f)" % (i*4, a[i], b[i], d[i]))
