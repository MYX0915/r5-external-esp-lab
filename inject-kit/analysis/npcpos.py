import numpy as np, glob, os
for f in sorted(glob.glob(r"C:\ProgramData\scdump\7_*.bin")):
    raw=open(f,"rb").read()
    va=os.path.basename(f).split("_")[1].split(".")[0]
    for off in (0x1F78, 0x376C):
        v=np.frombuffer(raw[off:off+12],dtype=np.float32)
        print("0x%-11s +0x%04X = (%9.2f,%9.2f,%9.2f)" % (va, off, v[0],v[1],v[2]))
    print()
