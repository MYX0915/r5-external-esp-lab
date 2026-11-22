import numpy as np, struct
with open(r"C:\ProgramData\scdump\10_182DA640.bin","rb") as fh:
    raw=fh.read()
a=np.fromfile(__import__("io").BytesIO(raw),dtype=np.float32)
with open(r"C:\ProgramData\sc_feed.bin","rb") as fh:
    f=fh.read()
cam=np.array(struct.unpack_from("<3f",f,8)); pos=np.array(struct.unpack_from("<3f",f,32))
print("cam=",["%.1f"%v for v in cam]," pos=",["%.1f"%v for v in pos])
for name,tgt in (("pos",pos),("cam",cam)):
    best=(1e9,0,None)
    for i in range(len(a)-3):
        v=a[i:i+3]
        if not np.isfinite(v).all(): continue
        d=float(np.linalg.norm(v-tgt))
        if d<best[0]: best=(d,i*4,v.copy())
    print(" closest to %-4s d=%8.1f at +0x%05X (%s)" % (name,best[0],best[1],
          ",".join("%.1f"%x for x in best[2]) if best[2] is not None else "-"))
