import numpy as np, glob, os, struct, time
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
me=np.array(struct.unpack_from("<3f",f,32))
print("my pos:", ["%.1f"%v for v in me])
rows=[]
for line in open("spread40.txt"):
    va=line.split()[0]; hexv=va[2:]
    fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x4000]
    if not fs: continue
    raw=open(fs[0],"rb").read()
    vt=struct.unpack_from("<Q", raw, 0)[0]
    p=struct.unpack_from("<3f", raw, 0x376C)
    ok = np.isfinite(p).all() and abs(p[0])>1 and abs(p[0])<100000 and abs(p[1])<100000
    if ok:
        d=float(np.linalg.norm(np.array(p)-me))
        rows.append((d,hexv,vt,p))
rows.sort()
print("entities with a plausible +0x376C:", len(rows))
for d,hexv,vt,p in rows[:10]:
    print("   0x%-10s vt=0x%-14X pos=(%10.1f,%10.1f,%10.1f) dist=%.0f" % (hexv,vt,p[0],p[1],p[2],d))
