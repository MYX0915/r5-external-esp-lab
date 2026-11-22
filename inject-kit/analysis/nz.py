import numpy as np, glob, os
for f in sorted(glob.glob(r"C:\ProgramData\scdump\13_*.bin"))[:6]:
    raw=np.fromfile(f,dtype=np.uint8)
    nz=int((raw!=0).sum())
    # first non-zero offset
    idx=np.nonzero(raw)[0]
    first=int(idx[0]) if len(idx) else -1
    print("%-22s nonZero=%6d/%6d  firstNZ=0x%X" % (os.path.basename(f), nz, len(raw), first))
