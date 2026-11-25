import struct, glob, os, numpy as np
e=int(open("other.txt").read().strip(),16)
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
pos=np.array(struct.unpack_from("<3f",f,32), dtype=np.float64)
print("??: (%.1f,%.1f,%.1f)" % (pos[0],pos[1],pos[2]))
print("???? 0x%X ???????:" % e)
n=0
for blk in range(0x6000,0x12000,0x1000):
    va=e+blk; hexv="%X"%va
    fs=sorted([x for x in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(x)==0x1000], key=os.path.getmtime)
    if not fs: continue
    raw=open(fs[-1],"rb").read()
    for off in range(0,0x1000-12,4):
        t=struct.unpack_from("<3f",raw,off)
        if not all(abs(x)<40000 for x in t): continue
        if not (200<abs(t[0])<20000 and abs(t[1])<20000 and -800<t[2]<3200): continue
        d=float(np.linalg.norm(np.array(t)-pos))*0.01905
        if d<400:
            print("  +0x%05X (%.1f,%.1f,%.1f) ??? %.1f?" % (blk+off,t[0],t[1],t[2],d))
            n+=1
            if n>15: break
    if n>15: break
print("?? %d" % n)
