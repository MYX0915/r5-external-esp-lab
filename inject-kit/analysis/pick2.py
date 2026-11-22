import numpy as np, glob, os, struct
cam=np.array(struct.unpack_from("<3f",open(r"C:\ProgramData\sc_feed.bin","rb").read(),8))
best=[]
for line in open("scan60.txt"):
    v=line.strip(); hexv=v[2:]
    fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x2000]
    if not fs: continue
    raw=open(max(fs,key=os.path.getmtime),"rb").read()
    if len(raw)<0x984: continue
    t=struct.unpack_from("<3f", raw, 0x978)
    if not np.isfinite(t).all(): continue
    if abs(t[0])<200 or abs(t[0])>40000: continue
    if abs(t[1])>40000 or abs(t[2])>40000: continue
    d=float(np.linalg.norm(np.array(t)-cam))
    if d<20000: best.append((d,v,t))
best.sort()
print("real candidates: %d" % len(best))
for d,v,t in best[:6]:
    print("   0x%-12s (%.1f,%.1f,%.1f) dist=%.0f" % (v,t[0],t[1],t[2],d))
if best: open("dummyaddr.txt","w").write(best[0][1][2:])
