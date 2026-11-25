import struct, glob, os, numpy as np
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
pos=np.array(struct.unpack_from("<3f",f,32), dtype=np.float64)
print("??: (%.1f,%.1f,%.1f)\n" % (pos[0],pos[1],pos[2]))
insts=[l.split()[0] for l in open(r"C:\ProgramData\sc_ents.txt") if l.startswith("0x")]
ds=[]
for t in insts:
    e=int(t,16); hexv="%X"%e
    fs=sorted([x for x in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(x)==0x1000], key=os.path.getmtime)
    if not fs: continue
    raw=open(fs[-1],"rb").read()
    p=np.array(struct.unpack_from("<3f",raw,0x978), dtype=np.float64)
    if not np.isfinite(p).all(): continue
    if abs(p[0])<1 and abs(p[1])<1: continue
    d=float(np.linalg.norm(p-pos))*0.01905
    ds.append((d,t,p))
ds.sort()
print("???????? %d ??????:" % len(ds))
for d,t,p in ds[:12]:
    print("  %7.1f ?  %s  (%.0f,%.0f,%.0f)" % (d,t,p[0],p[1],p[2]))
print("  ...")
for d,t,p in ds[-3:]:
    print("  %7.1f ?  %s" % (d,t))
import numpy as np
arr=np.array([d for d,_,_ in ds])
print("\n??: ?? %.0fm  ?? %.0fm  ?? %.0fm" % (arr.min(), np.median(arr), arr.max()))
print("190??: %d ?" % (arr<190).sum())
print("1100??: %d ?" % (arr<1100).sum())
