import struct, glob, os, numpy as np
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
me=np.array(struct.unpack_from("<3f",f,32), dtype=np.float64)
addrs=[l.strip() for l in open(r"C:\ProgramData\sc_addr.txt") if l.startswith("0x")]
far=[]
for a in addrs:
    e=int(a,16); hexv="%X"%e
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x1000], key=os.path.getmtime)
    if not fs: continue
    pos=struct.unpack_from("<3f", open(fs[-1],"rb").read(), 0x978)
    if not np.isfinite(pos).all(): continue
    d=float(np.linalg.norm(np.array(pos)-me))*0.01905
    if 120 < d < 150: far.append((d,a))
far.sort()
print("120~150 ??????:")
for d,a in far[:6]: print("  %.1fm  %s" % (d,a))
open("farents.txt","w").write("\n".join(a for _,a in far[:5]))
