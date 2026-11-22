import numpy as np, glob, os, struct, collections
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
inst=struct.unpack_from("<Q",f,56)[0]
cam=np.array(struct.unpack_from("<3f",f,8))
print("me inst=0x%X cam=(%.0f,%.0f,%.0f)" % (inst,cam[0],cam[1],cam[2]))
myvt=None
cls=collections.Counter(); pos=[]
for line in open("m.txt"):
    hexv=line.strip()[2:]
    fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x4000]
    if not fs: continue
    raw=open(max(fs,key=os.path.getmtime),"rb").read()
    vt=struct.unpack_from("<Q", raw, 0)[0]
    cls[vt]+=1
    if int(hexv,16)==inst: myvt=vt
    p978=struct.unpack_from("<3f", raw, 0x978)
    if np.isfinite(p978).all() and 300<abs(p978[0])<40000 and abs(p978[1])<40000 and abs(p978[2])<5000:
        pos.append((hexv,vt,p978,float(np.linalg.norm(np.array(p978)-cam))))
print("my vtable = 0x%X" % (myvt or 0))
print("classes: %d" % len(cls))
for vt,c in cls.most_common(6): print("   0x%X -> %d" % (vt,c))
print("\nobjects with valid +0x978: %d" % len(pos))
pos.sort(key=lambda x:x[3])
for hexv,vt,p,d in pos[:10]:
    print("   %6.0fm 0x%-10s vt=0x%-14X (%.0f,%.0f,%.0f)" % (d,hexv,vt,p[0],p[1],p[2]))
if myvt:
    same=[(h,v) for h,v,_,_ in pos if v==myvt]
    print("\nsame-class with valid position: %d" % len(same))
