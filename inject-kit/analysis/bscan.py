import numpy as np, glob, os
fs=[f for f in glob.glob(r"C:\ProgramData\scdump\7_*.bin") if os.path.getsize(f)==0x4000]
print("targets dumped:", len(fs))
def mat_at(a, off, stride):
    m=a[off//4: off//4+ (12 if stride==0x30 else 16)]
    if len(m) < (12 if stride==0x30 else 16): return None
    if not np.isfinite(m).all(): return None
    r0,r1,r2=m[0:3],m[4:7],m[8:11]
    for r in (r0,r1,r2):
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
    if hits:
        print("%-20s matrix hits=%d" % (os.path.basename(f), len(hits)))
        for stride,off,t in hits[:3]:
            print("     stride=0x%X +0x%05X t=(%9.1f,%9.1f,%9.1f)" % (stride,off,t[0],t[1],t[2]))
