import struct, glob, os, numpy as np
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
me=np.array(struct.unpack_from("<3f",f,32))
cam=np.array(struct.unpack_from("<3f",f,8))
print("me=(%.0f,%.0f,%.0f)" % tuple(me))
insts=[l.strip() for l in open("allinst.txt")]
hits=[]
for a in insts:
    hexv=a[2:]
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x1000], key=os.path.getmtime)
    if not fs: continue
    raw=open(fs[-1],"rb").read()
    p=struct.unpack_from("<3f", raw, 0x978)
    if not np.isfinite(p).all(): continue
    if abs(p[0])<1 and abs(p[1])<1: continue
    d=float(np.linalg.norm(np.array(p)-me))
    hits.append((d,a,p))
hits.sort()
print("?? 10 ???????:")
for d,a,p in hits[:10]:
    print("   %6.0f ??(%5.1fm)  0x%-12s (%.1f,%.1f,%.1f)" % (d,d*0.01905,a[2:],p[0],p[1],p[2]))
open("close.txt","w").write("\n".join(a for _,a,_ in hits[:6]))
