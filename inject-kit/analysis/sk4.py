import numpy as np, glob, os
def runs(a, stride=0x30, need=20, cluster=400.0):
    n=(len(a)*4)//stride
    best=0; bestAt=-1; cur=0; start=0
    for i in range(n):
        m=a[i*12:(i+1)*12]
        if len(m)<12 or not np.isfinite(m).all():
            cur=0; continue
        t=np.array([m[3],m[7],m[11]])
        if np.abs(t).max()>20000 or np.abs(t).max()<0.5:
            cur=0; continue
        if cur and float(np.linalg.norm(t-prev))<cluster: cur+=1
        else: cur=1; start=i
        prev=t
        if cur>best: best=cur; bestAt=start
    return (best,bestAt) if best>=need else None
for va in ("E4A95440","141E6C10"):
    fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%va) if os.path.getsize(p)==0x10000]
    if not fs: print("  %s: no 64KB dump" % va); continue
    a=np.fromfile(max(fs,key=os.path.getmtime),dtype=np.float32)
    r=runs(a)
    print("  %-10s floats=%d  bone-like run: %s" % (va, len(a), ("%d mats at +0x%X" % (r[0], r[1]*0x30)) if r else "none"))
