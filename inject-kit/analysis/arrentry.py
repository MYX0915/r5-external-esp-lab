import struct, glob, os, numpy as np
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
me=np.array(struct.unpack_from("<3f",f,32), dtype=np.float64)
print("me=(%.1f,%.1f,%.1f)\n" % (me[0],me[1],me[2]))
for b in ("282FE040","2770A580","282FC6C0","B9B5C0"):
    base=int(b,16)
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%b) if os.path.getsize(p)==0x200], key=os.path.getmtime)
    if not fs: print("0x%s ?dump" % b); continue
    raw=open(fs[-1],"rb").read()
    print("=== 0x%s ===" % b)
    # ??? 0x40????????????
    for k in range(3):
        e=k*0x40
        found=[]
        for off in range(0,0x40-12,4):
            v=struct.unpack_from("<3f", raw, e+off)
            if abs(v[0])>100 and abs(v[0])<20000 and abs(v[1])<20000 and -500<v[2]<3000:
                found.append((off,v))
        if found:
            for off,v in found[:2]:
                d=float(np.linalg.norm(np.array(v)-me))
                print("  ??%d +0x%02X  (%.1f,%.1f,%.1f)  ?%.1f?" % (k,off,v[0],v[1],v[2],d*0.01905))
    print()
