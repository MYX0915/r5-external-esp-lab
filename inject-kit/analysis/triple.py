import numpy as np, glob, os, struct
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_12469B1C0.bin") if os.path.getsize(p)==0x4000], key=os.path.getmtime)[-8:]
cam=np.array(struct.unpack_from("<3f",open(r"C:\ProgramData\sc_feed.bin","rb").read(),8))
print("cam:", ["%.1f"%v for v in cam])
print("\n+0x2480 ????:")
for p in fs:
    raw=open(p,"rb").read()
    t=struct.unpack_from("<3f", raw, 0x248C)
    print("   (%.2f, %.2f, %.2f)" % t)
print("\n+0x978 ????????:")
for p in fs:
    raw=open(p,"rb").read()
    t=struct.unpack_from("<3f", raw, 0x978)
    print("   (%.2f, %.2f, %.2f)" % t)
