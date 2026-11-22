import numpy as np, glob, os, struct, time
pos=None
for _ in range(60):
    f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
    if len(f)>=64 and struct.unpack_from("<I",f,48)[0]:
        p=np.array(struct.unpack_from("<3f",f,32))
        if np.isfinite(p).all() and np.abs(p).sum()>1: pos=p; break
    time.sleep(0.15)
print("player pos=", None if pos is None else ["%.1f"%v for v in pos])
if pos is not None:
    vas=["182DA640","3A7C76D0","3A7C7730","EDD1F3D0","1676BF00","138D9920","138D9900","C92414B0","C9241560","C9241610"]
    for va in vas:
        fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%va) if os.path.getsize(p)>=0x1000]
        if not fs: continue
        f2=max(fs, key=os.path.getmtime)
        a=np.fromfile(f2,dtype=np.float32)
        n=(len(a)//12)*12
        best=None
        for i in range(0, n-12+1, 12):
            m=a[i:i+12]
            if not np.isfinite(m).all(): continue
            t=np.array([m[3],m[7],m[11]])
            if np.abs(t).sum() < 1: continue
            d=float(np.linalg.norm(t-pos))
            if best is None or d<best[0]: best=(d,i,m.copy())
        if best:
            d,i,m=best
            print("  0x%-9s nearest d=%9.1f at +0x%05X t=(%8.1f,%8.1f,%8.1f)" % (va,d,i*4,m[3],m[7],m[11]))
