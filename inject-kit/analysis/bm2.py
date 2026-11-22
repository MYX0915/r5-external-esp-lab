import numpy as np, glob, os, struct
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
pos=np.array(struct.unpack_from("<3f",f,32)); cam=np.array(struct.unpack_from("<3f",f,8))
print("player pos=",["%.1f"%v for v in pos])
vas=["182DA640","3A7C76D0","3A7C7730","EDD1F3D0","1676BF00","138D9920","138D9900","C92414B0","C9241560","C9241610"]
for va in vas:
    fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%va) if os.path.getsize(p)>=0x1000]
    if not fs: print(" 0x%s: no file" % va); continue
    f2=max(fs, key=os.path.getmtime)
    a=np.fromfile(f2,dtype=np.float32)
    n=(len(a)//12)*12
    best=None
    for i in range(0, n-12, 12):
        m=a[i:i+12]
        if not np.isfinite(m).all(): continue
        t=np.array([m[3],m[7],m[11]])
        d=float(np.linalg.norm(t-pos))
        if best is None or d<best[0]: best=(d,i)
    if best:
        d,i=best
        m=a[i:i+12]
        print("  0x%-9s nearest bone-translation d=%8.1f at +0x%05X t=(%8.1f,%8.1f,%8.1f)" % (va,d,i*4,m[3],m[7],m[11]))
