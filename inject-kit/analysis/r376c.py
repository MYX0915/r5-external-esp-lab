import struct, glob, os, numpy as np
me=int(open("me.txt").read().strip(),16)
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
pos=np.array(struct.unpack_from("<3f",f,32), dtype=np.float64)
insts=[l.split()[0] for l in open(r"C:\ProgramData\sc_ents.txt") if l.startswith("0x")]
print("?? feed: (%.1f,%.1f,%.1f)" % (pos[0],pos[1],pos[2]))
print("???? 0x%X +0x376C:" % me)
def rd(e,off):
    blk = off & ~0xFFF
    hexv="%X"%(e+blk)
    fs=sorted([x for x in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(x)==0x1000], key=os.path.getmtime)
    if not fs: return None
    raw=open(fs[-1],"rb").read()
    fo=off-blk
    if fo+12>len(raw): return None
    return struct.unpack_from("<3f",raw,fo)
v=rd(me,0x376C)
print("  ", v)
print("\n??????:")
for x in [i for i in insts if int(i,16)!=me][:4]:
    e=int(x,16)
    for off in (0x376C,0x3780,0x978):
        r=rd(e,off)
        if r and any(abs(q)>1 for q in r):
            d=float(np.linalg.norm(np.array(r)-pos))*0.01905
            print("  0x%X +0x%04X = (%.1f,%.1f,%.1f) ??? %.1f?" % (e,off,r[0],r[1],r[2],d))
