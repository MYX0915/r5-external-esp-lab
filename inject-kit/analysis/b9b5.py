import struct, glob, os, numpy as np
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
me=np.array(struct.unpack_from("<3f",f,32), dtype=np.float64)
base=0xB9B5D0; stride=0x30; off=0x08
hexv="B9B5A0"
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x600], key=os.path.getmtime)
raw=open(fs[-1],"rb").read()
print("me=(%.1f,%.1f,%.1f)\n" % (me[0],me[1],me[2]))
start=base-0x30   # dump ???base ? +0x30
print("0xB9B5D0 ?????0x30???+0x08?:")
for k in range(20):
    e=(base-0x8)+k*stride   # ???? = base-0x8
    idx=e-(start)
    if idx<0 or idx+stride>len(raw): break
    v=struct.unpack_from("<3f", raw, idx+off)
    d=float(np.linalg.norm(np.array(v)-me))
    print("  [%2d] base=0x%X  (%.1f, %.1f, %.1f)  ? %.1f ?" % (k, e, v[0],v[1],v[2], d*0.01905))
