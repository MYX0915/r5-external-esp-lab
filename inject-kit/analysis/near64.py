import struct, glob, os, numpy as np, math
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
    d=float(np.linalg.norm(np.array(p)-me))
    res.append((d,a,p))
res.sort()
print("me=(%.0f,%.0f,%.0f)  ? %d ????" % (me[0],me[1],me[2],len(res)))
print("\n??? 8 ?:")
for d,a,p in res[:8]:
    print("   %5.0f ??(%5.1fm)  %s  (%.0f,%.0f,%.0f)" % (d,d*0.01905,a,p[0],p[1],p[2]))
open("targets4.txt","w").write("\n".join(a for _,a,_ in res[:4]))
print("\n??? targets4.txt??? 4 ??")
