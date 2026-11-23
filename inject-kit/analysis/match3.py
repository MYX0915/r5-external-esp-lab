import struct, glob, os, numpy as np
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
me=np.array(struct.unpack_from("<3f",f,32))
cnt=struct.unpack_from("<I",f,44)[0]
print("me=(%.0f,%.0f,%.0f)  feed ?? %d ?" % (me[0],me[1],me[2],cnt))
targets=[struct.unpack_from("<3f", f, 64+i*12) for i in range(cnt)]
# ?? feed ?? ? 926 ? dump ? +0x978 ??
insts=[l.strip() for l in open("allinst.txt")]
db=[]
for a in insts:
    hexv=a[2:]
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x800], key=os.path.getmtime)
    if not fs: continue
    raw=open(fs[-1],"rb").read()
    p=struct.unpack_from("<3f", raw, 0x978)
    if np.isfinite(p).all() and abs(p[0])>1:
        db.append((a,np.array(p)))
print("??????: %d" % len(db))
print("\n??? feed ???????:")
seen=set()
for t in targets[:10]:
    best=None
    for a,p in db:
        d=float(np.linalg.norm(p-np.array(t)))
        if best is None or d<best[0]: best=(d,a)
    if best and best[0]<50 and best[1] not in seen:
        seen.add(best[1])
        dist=float(np.linalg.norm(np.array(t)-me))
        print("   ??(%.0f,%.0f,%.0f) ??%.0f?? ? ?? %s (?%.1f)" % (t[0],t[1],t[2],dist,best[1],best[0]))
open("three.txt","w").write("\n".join(sorted(seen, key=lambda x: 0))[:400])
print("\n??? three.txt: %d ?" % len(seen))
