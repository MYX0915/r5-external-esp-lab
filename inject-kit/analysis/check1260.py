import struct, glob, os, numpy as np
me=int(open("inst_now.txt").read().strip(),16)
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
pos=np.array(struct.unpack_from("<3f",f,32), dtype=np.float64)
print("?? feed ??: (%.2f,%.2f,%.2f)\n" % (pos[0],pos[1],pos[2]))
insts=[l.split()[0] for l in open(r"C:\ProgramData\sc_ents.txt") if l.startswith("0x")]
targets=[hex(me)] + [i for i in insts if int(i,16)!=me][:3]
for t in targets:
    e=int(t,16)
    hexv="%X"%(e+0x1000)
    fs=sorted([x for x in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(x)==0x1000], key=os.path.getmtime)
    if not fs: print("  0x%X ?dump" % e); continue
    raw=open(fs[-1],"rb").read()
    tag = "??" if e==me else "??"
    print("%s 0x%X:" % (tag,e))
    for mo in (0x1240,0x1250,0x1260,0x1270):
        fo=mo-0x1000
        if fo<0 or fo+12>len(raw): continue
        v=struct.unpack_from("<3f",raw,fo)
        d=float(np.linalg.norm(np.array(v)-pos))*0.01905 if all(np.isfinite(v)) else -1
        print("   +0x%04X (%.1f,%.1f,%.1f) ??? %.1f?" % (mo,v[0],v[1],v[2],d))
