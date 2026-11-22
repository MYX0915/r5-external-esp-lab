import numpy as np, glob, os
fs=sorted(glob.glob(r"C:\ProgramData\scdump\vd*.bin"), key=os.path.getmtime, reverse=True)[:4]
for f in fs:
    a=np.fromfile(f,dtype=np.float32)
    print("=== %s ===" % os.path.basename(f))
    for base in (0x110, 0x1780):
        vals=[a[(base//4)+k] for k in range(6)]
        print("   @0x%04X: %s" % (base, " ".join("%10.2f"%v for v in vals)))
