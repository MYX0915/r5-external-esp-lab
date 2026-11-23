import struct, glob, os, numpy as np
me=open("me.txt").read().strip()
addrs=[l.split()[0] for l in open(r"C:\ProgramData\sc_ents.txt") if l.strip()]
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
myp=np.array(struct.unpack_from("<3f",f,32))
print("me=%s pos=(%.0f,%.0f,%.0f)" % (me,myp[0],myp[1],myp[2]))
rows=[]
for a in addrs:
    hexv=a[2:]
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x4000], key=os.path.getmtime)
    if not fs: continue
    raw=open(fs[-1],"rb").read()
    p376=struct.unpack_from("<3f", raw, 0x376C)
    p978=struct.unpack_from("<3f", raw, 0x978)
    def ok(t): return np.isfinite(t).all() and abs(t[0])>100 and abs(t[0])<80000
    rows.append((a, p376 if ok(p376) else None, p978 if ok(p978) else None))
good376=[r for r in rows if r[1] is not None]
good978=[r for r in rows if r[2] is not None]
print("? +0x376C ??: %d" % len(good376))
for a,p,_ in good376[:8]:
    d=float(np.linalg.norm(np.array(p)-myp))
    print("   %s (%.1f,%.1f,%.1f) d=%.0f" % (a,p[0],p[1],p[2],d))
print("? +0x978 ??: %d" % len(good978))
for a,_,p in good978[:8]:
    d=float(np.linalg.norm(np.array(p)-myp))
    print("   %s (%.1f,%.1f,%.1f) d=%.0f" % (a,p[0],p[1],p[2],d))
