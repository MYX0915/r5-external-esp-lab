import numpy as np, glob, os
D=r"C:\ProgramData\scdump"
files=sorted(glob.glob(os.path.join(D,"6_*.bin")))
print("instances dumped:", len(files))
for f in files:
    raw=np.fromfile(f,dtype=np.uint8)
    va=int(os.path.basename(f).split("_")[1].split(".")[0],16)
    pos=np.frombuffer(raw[0x188:0x188+12],dtype=np.float32)
    tail=np.frombuffer(raw[0x180:0x1A0],dtype=np.float32)
    print("  0x%-11X  +0x188=(%9.2f,%9.2f,%9.2f)   ctx=%s" % (va,pos[0],pos[1],pos[2],
          " ".join("%.1f"%v for v in tail)))
