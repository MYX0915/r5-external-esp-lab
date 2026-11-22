import numpy as np, glob, os, struct
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
pos=np.array(struct.unpack_from("<3f",f,32))
print("player pos:", ["%.1f"%v for v in pos])
for va in ("E4A95440","141E6C10","13E8D2F0"):
    fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%va) if os.path.getsize(p)>=0x4000]
    if not fs: print("  %s: no dump" % va); continue
    a=np.fromfile(max(fs,key=os.path.getmtime),dtype=np.float32)
    n=len(a)//12
    m=a[:n*12].reshape(n,12)
    t=m[:, [3,7,11]]
    with np.errstate(over="ignore",invalid="ignore"):
        n0=np.linalg.norm(m[:,0:3],axis=1); n1=np.linalg.norm(m[:,4:7],axis=1); n2=np.linalg.norm(m[:,8:11],axis=1)
        orth=(np.abs(n0-1)<0.25)&(np.abs(n1-1)<0.25)&(np.abs(n2-1)<0.25)
        finite=np.isfinite(t).all(axis=1)
        d=np.linalg.norm(t-pos, axis=1)
    good = finite & orth & (d<2000)
    idx=np.nonzero(good)[0]
    print("  %-10s orthonormal&near-player matrices: %d" % (va, len(idx)))
    for i in idx[:4]:
        print("      +0x%05X t=(%9.1f,%9.1f,%9.1f) dist=%.0f" % (i*0x30, t[i][0],t[i][1],t[i][2], d[i]))
