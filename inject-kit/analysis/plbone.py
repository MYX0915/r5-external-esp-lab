import numpy as np, glob, os
f=[p for p in glob.glob(r"C:\ProgramData\scdump\*_EA3F9450.bin") if os.path.getsize(p)>=0x20000]
print("file:", [os.path.basename(x) for x in f])
a=np.fromfile(f[0],dtype=np.float32)
print("floats:", len(a))
def mat_at(a, off, stride):
    need = 12 if stride==0x30 else 16
    if off//4+need > len(a): return None
    m=a[off//4: off//4+need]
    if not np.isfinite(m).all(): return None
    with np.errstate(over="ignore", invalid="ignore"):
        for r in (m[0:3],m[4:7],m[8:11]):
            n=float(np.linalg.norm(r))
            if not (0.9<n<1.1): return None
    t = np.array([m[3],m[7],m[11]]) if stride==0x30 else np.array([m[12],m[13],m[14]])
    if np.abs(t).max()>12000 or np.abs(t).max()<50: return None
    return t
for stride in (0x30, 0x40):
    hits=[]
    for off in range(0, len(a)*4-stride*8, 4):
        t=mat_at(a,off,stride)
        if t is not None: hits.append((off,t))
    runs=[]
    if hits:
        s=hits[0][0]; p=s
        for off,t in hits[1:]:
            if off==p+stride: p=off; continue
            runs.append((s,p)); s=off; p=off
        runs.append((s,p))
        runs.sort(key=lambda r:-(r[1]-r[0]))
    print("stride=0x%X hits=%d longest run=%s" % (stride, len(hits), ("0x%X..0x%X (%d)" % (runs[0][0],runs[0][1],(runs[0][1]-runs[0][0])//stride+1)) if runs else "none"))
    for off,t in hits[:3]:
        print("    +0x%05X t=(%9.1f,%9.1f,%9.1f)" % (off,t[0],t[1],t[2]))
