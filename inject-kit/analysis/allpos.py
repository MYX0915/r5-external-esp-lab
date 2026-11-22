import numpy as np, glob, os, struct, collections
cam=np.array(struct.unpack_from("<3f",open(r"C:\ProgramData\sc_feed.bin","rb").read(),8))
rows=[]; cls=collections.Counter()
for line in open("cur.txt"):
    hexv=line.strip()[2:]
    fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x4000]
    if not fs: continue
    raw=open(max(fs,key=os.path.getmtime),"rb").read()
    vt=struct.unpack_from("<Q", raw, 0)[0]
    cls[vt]+=1
    p376=struct.unpack_from("<3f", raw, 0x376C)
    p978=struct.unpack_from("<3f", raw, 0x978)
    ok376 = np.isfinite(p376).all() and abs(p376[0])>1
    ok978 = np.isfinite(p978).all() and abs(p978[0])>1
    if ok376 or ok978:
        rows.append((hexv,vt,p376 if ok376 else None,p978 if ok978 else None))
print("classes:", len(cls))
for vt,c in cls.most_common(5): print("   0x%X -> %d" % (vt,c))
print("\nentities with a position (376C or 978): %d" % len(rows))
for v,vt,a,b in rows[:12]:
    sa = "(%.0f,%.0f,%.0f)"%tuple(a) if a is not None else "-"
    sb = "(%.0f,%.0f,%.0f)"%tuple(b) if b is not None else "-"
    print("   0x%-10s vt=0x%-14X 376C=%-22s 978=%s" % (v,vt,sa,sb))
