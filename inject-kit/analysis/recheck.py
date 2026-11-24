import numpy as np, glob, os, struct
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_3AF1AAE0.bin") if os.path.getsize(p)==0x1000], key=os.path.getmtime)[-1:]
for p in fs:
    d=open(p,'rb').read()
    nz=sum(1 for i in range(0,min(len(d),256),4) if d[i:i+4]!=b'\x00\x00\x00\x00')
    print("%s ?256????dword=%d" % (os.path.basename(p), nz))
    print("  +0x978 = %s" % (struct.unpack_from("<3f", d, 0x978),))
