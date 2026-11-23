import numpy as np, glob, os
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
import struct
cam=struct.unpack_from("<3f",f,8)
print("cam=(%.3f,%.3f,%.3f)" % cam)
files=[p for p in glob.glob(r"C:\ProgramData\scdump\*_h*.bin") if os.path.getsize(p)>0x100000]
files.sort(key=os.path.getmtime, reverse=True)
hits=[]
for p in files[:20]:
    a=np.fromfile(p, dtype=np.float32)
    m=(np.abs(a-cam[0])<0.5)
    idx=np.nonzero(m)[0]
    for i in idx[:6]:
        if i+2 >= len(a): continue
        if abs(a[i+1]-cam[1])<0.5 and abs(a[i+2]-cam[2])<0.5:
            hits.append((os.path.basename(p), int(i*4)))
print("?????????:", len(hits))
for nm,off in hits[:10]:
    print("   %-22s +0x%06X" % (nm,off))
    a=np.fromfile(r"C:\ProgramData\scdump\%s"%nm, dtype=np.float32)
    i=off//4
    print("      ?: %s" % " ".join("%.3f"%v for v in a[max(0,i-3):i]))
    print("      ?: %s" % " ".join("%.3f"%v for v in a[i:i+9]))
