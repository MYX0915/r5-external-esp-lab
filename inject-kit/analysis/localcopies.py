import struct, glob, os, numpy as np
me=0xF702D940
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
pos=np.array(struct.unpack_from("<3f",f,32), dtype=np.float64)
print("????: (%.1f,%.1f,%.1f)\n" % (pos[0],pos[1],pos[2]))
print("?????????????????:")
n=0
for blk in (0x0,0x1000,0x2000,0x3000,0x4000,0x5000,0x6000,0x7000):
    va=me+blk; hexv="%X"%va
    fs=sorted([x for x in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(x)==0x1000], key=os.path.getmtime)
    if not fs: continue
    raw=open(fs[-1],"rb").read()
    for off in range(0,0x1000-12,4):
        t=np.array(struct.unpack_from("<3f",raw,off), dtype=np.float64)
        if not np.isfinite(t).all(): continue
        d=float(np.linalg.norm(t-pos))
        if d < 3.0:
            print("  +0x%05X  (%.2f,%.2f,%.2f)  ?? %.2f" % (blk+off,t[0],t[1],t[2],d))
            n+=1
print("\n? %d ?" % n)
