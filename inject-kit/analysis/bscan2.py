import numpy as np, glob, os
fs=[f for f in glob.glob(r"C:\ProgramData\scdump\8_*.bin") if os.path.getsize(f)>=0x1000]
print("targets:", len(fs))
def mat_at(a, off, stride):
    need = 12 if stride==0x30 else 16
    if off//4+need > len(a): return None
    m=a[off//4: off//4+need]
    if not np.isfinite(m).all(): return None
    with np.errstate(over='ignore', invalid='ignore'):
        for r in (m[0:3],m[4:7],m[8:11]):
            n=float(np.linalg.norm(r))
            if not (0.9<n<1.1): return None
    t = np.array([m[3],m[7],m[11]]) if stride==0x30 else np.array([m[12],m[13],m[14]])
    if np.abs(t).max()>12000 or np.abs(t).max()<50: return None
    return t
for f in fs:
    a=np.fromfile(f,dtype=np.float32)
    hits=[]
    for stride in (0x30,0x40):
        for off in range(0, len(a)*4-stride*8, 4):
            t=mat_at(a,off,stride)
            if t is not None: hits.append((stride,off,t))
    print("%-20s hits=%d" % (os.path.basename(f), len(hits)))
    for stride,off,t in hits[:2]:
        print("     stride=0x%X +0x%05X t=(%9.1f,%9.1f,%9.1f)" % (stride,off,t[0],t[1],t[2]))
