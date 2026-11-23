import struct, glob, os, numpy as np
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
me=np.array(struct.unpack_from("<3f",f,32))
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
    if abs(p[0])<100 or abs(p[0])>80000: continue
    d=float(np.linalg.norm(np.array(p)-me))
    if d<2500: hits.append((d,a,p))
hits.sort()
print("??(<2500??=47m)???: %d" % len(hits))
for d,a,p in hits[:15]:
    print("   %6.0f ??? 0x%-12s (%.0f,%.0f,%.0f)" % (d,a[2:],p[0],p[1],p[2]))
open("near.txt","w").write("\n".join(a for _,a,_ in hits[:10]))
