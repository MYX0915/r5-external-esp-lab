import struct, glob, os, numpy as np
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
me=np.array(struct.unpack_from("<3f",f,32))
samples=['0xF79E4EE0','0x12BE14570','0xF7BD6520','0x120296180','0xF7BC0310','0x130209B40','0x120297460','0x120060B30','0x12004A240','0xCC77A820','0x1301D3760']
print("me=(%.0f,%.0f,%.0f)\n" % tuple(me))
res=[]
for s in samples:
    hexv=s[2:]
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x1000], key=os.path.getmtime)
    if not fs: print("  %s ? dump" % s); continue
    raw=open(fs[-1],"rb").read()
    pos=struct.unpack_from("<3f", raw, 0x978)
    if not np.isfinite(pos).all() or (abs(pos[0])<1 and abs(pos[1])<1):
        print("  %s ?????" % s); continue
    d=float(np.linalg.norm(np.array(pos)-me))
    res.append((d,s,pos))
res.sort()
for d,s,p in res:
    print("  %6.1f m  %s  (%.0f,%.0f,%.0f)" % (d*0.01905,s,p[0],p[1],p[2]))
open("loot.txt","w").write("\n".join(s for _,s,_ in res[:5]))
