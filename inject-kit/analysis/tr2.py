import numpy as np, glob, os
for f in sorted(glob.glob(r"C:\ProgramData\scdump\11_*.bin"))+sorted(glob.glob(r"C:\ProgramData\scdump\12_*.bin")):
    if os.path.getsize(f)<0x1000: continue
    a=np.fromfile(f,dtype=np.float32)
    if len(a) > 0xCC0//4+3:
        v=a[0xCC0//4:0xCC0//4+3]
        print("%-20s +0xCC0 = (%9.2f,%9.2f,%9.2f)" % (os.path.basename(f), v[0],v[1],v[2]))
