import struct, glob, os, numpy as np
def verdict(meta):
    try:
        for line in open(meta, errors="replace"):
            if line.startswith("#summary"):
                for t in line.split():
                    if t.startswith("verdict="): return t.split("=")[1]
    except Exception: pass
    return None

f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
me=np.array(struct.unpack_from("<3f",f,32))
addrs=[l.strip() for l in open(r"C:\ProgramData\sc_addr.txt") if l.strip()]
res=[]; ok=bad=0
for a in addrs:
    hexv=a[2:]
    fs=sorted(glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv), key=os.path.getmtime)
    if not fs: continue
    binp=fs[-1]; metap=binp+".meta"
    v=verdict(metap) if os.path.exists(metap) else None
    if v!="COMPLETE": bad+=1; continue
    ok+=1
    raw=open(binp,"rb").read()
    p=struct.unpack_from("<3f", raw, 0x978)
    if not np.isfinite(p).all(): continue
    if abs(p[0])<1 and abs(p[1])<1: continue
    d=float(np.linalg.norm(np.array(p)-me))
    res.append((d,a,p))
res.sort()
print("me=(%.0f,%.0f,%.0f)  ???? %d / ?? %d" % (me[0],me[1],me[2],ok,bad))
print("\n??? 6 ??? COMPLETE ???:")
for d,a,p in res[:6]:
    print("   %5.1f ?  %s  (%.0f,%.0f,%.0f)" % (d*0.01905,a,p[0],p[1],p[2]))
open("t4.txt","w").write("\n".join(a for _,a,_ in res[:4]))
