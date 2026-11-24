import struct, glob, os, numpy as np
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
me=np.array(struct.unpack_from("<3f",f,32), dtype=np.float64)
loots=[l.strip() for l in open("loot_all.txt") if l.startswith("0x")]
print("me=(%.1f,%.1f,%.1f)  ?? %d\n" % (me[0],me[1],me[2],len(loots)))
hits=[]
for l in loots:
    e=int(l,16); hexv="%X"%e
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x200], key=os.path.getmtime)
    if not fs: continue
    raw=open(fs[-1],"rb").read()
    for off in range(0,0x200-12+1,4):
        v=struct.unpack_from("<3f", raw, off)
        if not all(np.isfinite(v)): continue
        if not (100<abs(v[0])<20000 and abs(v[1])<20000 and -500<v[2]<3000): continue
        d=float(np.linalg.norm(np.array(v)-me))
        if d < 400:   # 7.6 ??
            hits.append((d, l, off, v))
hits.sort()
print("???????? <7.6 ???????: %d ?" % len(hits))
for d,l,off,v in hits[:20]:
    print("  %-14s +0x%03X  (%.1f, %.1f, %.1f)  ? %.2f ?" % (l, off, v[0],v[1],v[2], d*0.01905))
