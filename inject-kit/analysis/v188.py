import numpy as np, glob, os
for f in sorted(glob.glob(r"C:\ProgramData\scdump\13_*.bin"))[:6]:
    if os.path.getsize(f) < 0x200: continue
    a=np.fromfile(f,dtype=np.float32)
    v=a[0x188//4:0x188//4+3]
    print("%-20s +0x188 = (%10.2f,%10.2f,%10.2f)" % (os.path.basename(f), v[0],v[1],v[2]))
print()
for f in sorted(glob.glob(r"C:\ProgramData\scdump\7_*.bin"))[:1]:
    a=np.fromfile(f,dtype=np.float32)
    v=a[0x188//4:0x188//4+3]
    print("player %-14s +0x188 = (%10.2f,%10.2f,%10.2f)" % (os.path.basename(f), v[0],v[1],v[2]))
