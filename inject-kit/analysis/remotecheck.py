import struct, glob, os, numpy as np
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
pos=np.array(struct.unpack_from("<3f",f,32), dtype=np.float64)
print("??: (%.1f,%.1f,%.1f)\n" % (pos[0],pos[1],pos[2]))
for e in (0x132D22B80, 0x132D27800):
    print("???? 0x%X:" % e)
    got=False
    for blk in (0x0,0x1000,0x2000,0x3000):
        va=e+blk; hexv="%X"%va
        fs=sorted([x for x in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(x)==0x1000], key=os.path.getmtime)
        if not fs: continue
        raw=open(fs[-1],"rb").read()
        # ??????
        if blk==0x3000:
            for mo in (0x376C,0x3780):
                fo=mo-0x3000
                v=struct.unpack_from("<3f",raw,fo)
                d=float(np.linalg.norm(np.array(v)-pos))*0.01905
                print("   +0x%04X (%.2f,%.2f,%.2f) ??? %.1f?" % (mo,v[0],v[1],v[2],d))
        # ????????
        for off in range(0,0x1000-12,4):
            t=struct.unpack_from("<3f",raw,off)
            if not all(abs(x)<40000 for x in t): continue
            if not (100<abs(t[0])<20000 and abs(t[1])<20000 and -500<t[2]<3000): continue
            d=float(np.linalg.norm(np.array(t)-pos))*0.01905
            if d<200:
                print("   [??] +0x%05X (%.1f,%.1f,%.1f) ??? %.1f?" % (blk+off,t[0],t[1],t[2],d))
                got=True
    if not got: print("   ?0x0~0x4000 ?? 200 ??????")
    print()
