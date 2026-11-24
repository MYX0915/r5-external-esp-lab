import struct, glob, os, numpy as np
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
me=np.array(struct.unpack_from("<3f",f,32))
addrs=[l.strip() for l in open(r"C:\ProgramData\sc_addr.txt") if l.strip()]
res=[]
for a in addrs:
    hexv=a[2:]
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x1000], key=os.path.getmtime)
    if not fs: continue
    raw=open(fs[-1],"rb").read()
    vt=struct.unpack_from("<Q", raw, 0)[0]
    pos=struct.unpack_from("<3f", raw, 0x978)
    if not np.isfinite(pos).all() or (abs(pos[0])<1 and abs(pos[1])<1): continue
    d=float(np.linalg.norm(np.array(pos)-me))
    res.append((d,a,vt,pos))
res.sort()
print("me=(%.0f,%.0f,%.0f)  ????? %d ?\n" % (me[0],me[1],me[2],len(res)))
print("?? 12 ?????????????:")
for d,a,vt,pos in res[:12]:
    print("  %6.1f m  %s  vt=0x%X  (%.0f,%.0f,%.0f)" % (d*0.01905,a,vt,pos[0],pos[1],pos[2]))
