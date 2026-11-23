import numpy as np, glob, os
vals=[float(x) for x in open("basis.txt").read().split()]
rx,ry,rz,ux,uy,uz,fx,fy,fz,cx,cy,cz = vals[:12]
files=[p for p in glob.glob(r"C:\ProgramData\scdump\*_h*.bin") if os.path.getsize(p)>0x100000]
files.sort(key=os.path.getmtime, reverse=True)
print("heap files:", len(files))
hits=[]
for p in files[:16]:
    a=np.fromfile(p, dtype=np.float32)
    n=len(a)
    # ? right.x ? right.y ??
    m=(np.abs(a[:-1]-rx)<0.002)&(np.abs(a[1:]-ry)<0.002)
    idx=np.nonzero(m)[0]
    for i in idx[:5]:
        seg=[float(v) for v in a[i:i+12]]
        hits.append((os.path.basename(p), int(i*4), seg))
print("right(x,y) ??:", len(hits))
for nm,off,seg in hits[:8]:
    print("   %-22s +0x%06X  %s" % (nm,off," ".join("%9.4f"%v for v in seg[:8])))
