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
    p=struct.unpack_from("<3f", raw, 0x978)
    if not np.isfinite(p).all(): continue
    if abs(p[0])<1 and abs(p[1])<1: continue
    d=float(np.linalg.norm(np.array(p)-me))
    if d>30000: continue
    res.append((d,a,p))
res.sort()
print("me=(%.0f,%.0f,%.0f)  ???? %d ?" % (me[0],me[1],me[2],len(res)))
print("\n??? 6 ?:")
for d,a,p in res[:6]:
    print("   %5.1f ?   %s   (%.0f,%.0f,%.0f)" % (d*0.01905, a, p[0],p[1],p[2]))
