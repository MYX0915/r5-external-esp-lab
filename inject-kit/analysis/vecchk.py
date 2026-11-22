import numpy as np, glob, os
fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_1C98C000F328.bin") if os.path.getsize(p)>=0x1000]
print("files:", [(os.path.basename(x), os.path.getsize(x)) for x in fs])
if fs:
    a=np.fromfile(fs[0],dtype=np.float32)
    nz=np.count_nonzero(a)
    print("non-zero floats: %d / %d" % (nz, len(a)))
    print("first 12 floats:", ["%.2f"%v for v in a[:12]])
    if nz:
        hits=[(i*4, a[i:i+3]) for i in range(len(a)-3) if np.isfinite(a[i:i+3]).all() and 1<abs(a[i])<20000]
        print("plausible vec3 count:", len(hits))
        for off,v in hits[:5]:
            print("   +0x%04X (%9.2f,%9.2f,%9.2f)" % (off,v[0],v[1],v[2]))
