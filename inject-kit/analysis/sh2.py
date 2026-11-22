import numpy as np, glob, os, struct, time
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
pos=np.array(struct.unpack_from("<3f",f,32))
print("player pos:", ["%.1f"%v for v in pos])
fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_C9F336E0.bin") if os.path.getsize(p)>=0x1000]
a=np.fromfile(fs[0],dtype=np.float32)
n=(len(a)//3)
best=(1e9,0,None)
for i in range(n-3):
    v=a[i:i+3]
    if not np.isfinite(v).all(): continue
    d=float(np.linalg.norm(v-pos))
    if d<best[0]: best=(d,i*4,v.copy())
print("closest vec3 to player pos in studioHdr obj: d=%.1f at +0x%X (%s)" % (best[0],best[1],
      ",".join("%.1f"%x for x in best[2]) if best[2] is not None else "-"))
# also chase its child pointers
raw=open(fs[0],"rb").read()
kids=[]
for i in range(0, min(len(raw),0x2000)-8, 8):
    v=struct.unpack_from("<Q", raw, i)[0]
    if 0x10000 < v < 0x7FFF00000000 and (v & 7)==0 and not (0x7FF776980000 <= v < 0x7FF790000000):
        kids.append((i,v))
print("child pointers:", len(kids))
open("kids.txt","w").write("\n".join("0x%X"%v for _,v in kids[:12]))
for off,v in kids[:8]: print("   +0x%03X -> 0x%X" % (off,v))
