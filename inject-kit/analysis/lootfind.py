import struct, glob, os, numpy as np
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
me=np.array(struct.unpack_from("<3f",f,32))
insts=[l.strip() for l in open("allinst.txt") if l.strip()]
res=[]
for a in insts:
    hexv=a[2:]
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x1000], key=os.path.getmtime)
    if not fs: continue
    raw=open(fs[-1],"rb").read()
    pos=struct.unpack_from("<3f", raw, 0x978)
    if not np.isfinite(pos).all(): continue
    if abs(pos[0])<1 and abs(pos[1])<1: continue
    d=float(np.linalg.norm(np.array(pos)-me))
    if d<500:
        vt=struct.unpack_from("<Q", raw, 0)[0]
        # ????
        n=0
        while n<32 and 32<=raw[0x590+n]<127: n+=1
        name=raw[0x590:0x590+n].decode('latin1')
        res.append((d,a,vt,name,pos))
res.sort()
print("me=(%.0f,%.0f,%.0f)  10???? %d ?:\n" % (me[0],me[1],me[2],len(res)))
for d,a,vt,name,pos in res[:15]:
    print("  %5.2f m  %s  vt=0x%X  name=%-18s" % (d*0.01905,a,vt,name if name else "(?)"))
open("lootcand.txt","w").write("\n".join(a for _,a,_,_,_ in res[:15]))
