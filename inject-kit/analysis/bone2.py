import numpy as np, glob, os
def is_matrix(a, off, stride, tmode):
    # returns translation or None
    if tmode == "3x4":
        m = a[off//4: off//4+12]
        if len(m) < 12: return None
        r0,r1,r2 = m[0:3], m[4:7], m[8:11]
        t = np.array([m[3], m[7], m[11]])
    else:
        m = a[off//4: off//4+16]
        if len(m) < 16: return None
        r0,r1,r2 = m[0:3], m[4:7], m[8:11]
        t = np.array([m[12], m[13], m[14]])
    if not np.isfinite(m).all(): return None
    for r in (r0,r1,r2):
        n = np.linalg.norm(r)
        if not (0.9 < n < 1.1): return None
    if np.abs(t).max() > 12000: return None
    if np.abs(t).max() < 100: return None
    return t
for f in sorted(glob.glob(r"C:\ProgramData\scdump\vd*.bin"), key=os.path.getmtime, reverse=True)[:4]:
    a=np.fromfile(f,dtype=np.float32)
    print("=== %s (%d floats) ===" % (os.path.basename(f), len(a)))
    for stride in (0x30, 0x40):
        for tmode in ("3x4","4x4"):
            if tmode=="3x4" and stride!=0x30: continue
            if tmode=="4x4" and stride!=0x40: continue
            found=[]
            for off in range(0, len(a)*4 - stride*4, 4):
                t=is_matrix(a, off, stride, tmode)
                if t is not None: found.append((off,t))
            # consecutive runs
            runs=[]
            if found:
                s=found[0][0]; p=s
                for off,t in found[1:]:
                    if off==p+stride: p=off; continue
                    runs.append((s,p)); s=off; p=off
                runs.append((s,p))
            runs.sort(key=lambda r:-(r[1]-r[0]))
            if runs:
                s,e=runs[0]
                print("   stride=0x%X %s : matches=%d, longest run 0x%X..0x%X (%d entries)" %
                      (stride, tmode, len(found), s, e, (e-s)//stride+1))
