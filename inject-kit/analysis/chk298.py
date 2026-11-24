import numpy as np, glob, os, struct
for a in ["0x3AF1AAE0","0x4037C280"]:
    hexv=a[2:]
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x2000], key=os.path.getmtime)[-60:]
    print("\n=== %s : +0x298 (qword) ??? ===" % a)
    out=[]
    for p in fs:
        raw=open(p,'rb').read()
        nz=sum(1 for i in range(0,256,4) if raw[i:i+4]!=b'\x00\x00\x00\x00')
        if nz==0: continue
        v=struct.unpack_from("<Q", raw, 0x298)[0]
        out.append(v)
    print("   ???? %d" % len(out))
    print("   " + " ".join("0x%X"%v if v else "0" for v in out[:24]))
