import struct, glob, os, numpy as np
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
me=np.array(struct.unpack_from("<3f",f,32), dtype=np.float64)
print("me=(%.1f,%.1f,%.1f)\n" % (me[0],me[1],me[2]))
for grp in ("weaponx","prop_loot_grabber"):
    fn="sig_%s.txt"%grp
    if not os.path.exists(fn): continue
    lst=[l.strip() for l in open(fn) if l.strip()]
    print("=== %s (%d) ===" % (grp,len(lst)))
    best=[]
    for v in lst:
        e=int(v,16); hexv="%X"%e
        fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x400], key=os.path.getmtime)
        if not fs: continue
        raw=open(fs[-1],"rb").read()
        for off in range(0,0x400-12+1,4):
            t=struct.unpack_from("<3f", raw, off)
            if not all(np.isfinite(t)): continue
            if not (100<abs(t[0])<20000 and abs(t[1])<20000 and -500<t[2]<3000): continue
            d=float(np.linalg.norm(np.array(t)-me))
            best.append((d, v, off, t))
    best.sort()
    for d,v,off,t in best[:6]:
        print("  %-14s +0x%03X (%.1f,%.1f,%.1f) ?%.2f?" % (v,off,t[0],t[1],t[2],d*0.01905))
    if not best: print("  ?????")
    print()
