import numpy as np, glob, os, struct
myvt=int(open("myvt.txt").read(),16)
cam=np.array(struct.unpack_from("<3f",open(r"C:\ProgramData\sc_feed.bin","rb").read(),8))
print("my vtable=0x%X  cam=(%.0f,%.0f,%.0f)\n" % (myvt,cam[0],cam[1],cam[2]))
same=[]
for line in open("cur.txt"):
    hexv=line.strip()[2:]
    fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x4000]
    if not fs: continue
    raw=open(max(fs,key=os.path.getmtime),"rb").read()
    vt=struct.unpack_from("<Q", raw, 0)[0]
    if vt!=myvt: continue
    p376=struct.unpack_from("<3f", raw, 0x376C)
    p978=struct.unpack_from("<3f", raw, 0x978)
    same.append((hexv,p376,p978,fs[-1]))
print("same-class instances: %d" % len(same))
for v,p376,p978,f in same:
    ok = np.isfinite(p376).all() and abs(p376[0])>1
    print("   0x%-10s +0x376C=%s   +0x978=(%.1f,%.1f,%.1f)" % (v,
          "(%.1f,%.1f,%.1f)"%tuple(p376) if ok else "ZERO/junk", p978[0],p978[1],p978[2]))
