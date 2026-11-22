import numpy as np, glob, os
fs=[f for f in glob.glob(r"C:\ProgramData\scdump\4_*.bin") if os.path.getsize(f)>0x1000]
print("object      +0x3C0    +0x714    +0x19C    +0x11CC")
for f in fs:
    a=np.fromfile(f,dtype=np.float32)
    print("%-12s %9.2f %9.2f %9.2f %9.3f" % (os.path.basename(f)[2:12], a[0x3C0//4], a[0x714//4], a[0x19C//4], a[0x11CC//4]))
