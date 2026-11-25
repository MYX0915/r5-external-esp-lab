import struct, glob, os, numpy as np
me=int(open("me.txt").read().strip(),16)
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
pos=np.array(struct.unpack_from("<3f",f,32), dtype=np.float64)
print("?? feed: (%.1f,%.1f,%.1f)\n" % (pos[0],pos[1],pos[2]))
insts=[l.split()[0] for l in open(r"C:\ProgramData\sc_ents.txt") if l.startswith("0x")]
targets=[("??",me)] + [(("??%s"%i), int(x,16)) for i,x in enumerate([v for v in insts if int(v,16)!=me][:2])]
for name,e in targets:
    print("%s 0x%X:" % (name,e))
    found=0
    for blk in (0x0,0x1000,0x2000,0x3000,0x4000):
        va=e+blk; hexv="%X"%va
        fs=sorted([x for x in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(x)==0x1000], key=os.path.getmtime)
        if not fs: continue
        raw=open(fs[-1],"rb").read()
        for off in range(0,0x1000-12,4):
            t=struct.unpack_from("<3f",raw,off)
            if not all(abs(x)<40000 for x in t): continue
            if not (200<abs(t[0])<20000 and abs(t[1])<20000 and -800<t[2]<3000): continue
            d=float(np.linalg.norm(np.array(t)-pos))*0.01905
            if d<300:
                print("   +0x%05X (%.1f,%.1f,%.1f) ??? %.1f?" % (blk+off,t[0],t[1],t[2],d))
                found+=1
    if not found: print("   ?0~0x5000 ???????")
    print()
