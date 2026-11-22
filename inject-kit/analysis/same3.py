import numpy as np, glob, os, struct, collections
myvt=int(open("vt3.txt").read(),16)
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
cam=np.array(struct.unpack_from("<3f",f,8)); pos=np.array(struct.unpack_from("<3f",f,32))
print("me=(%.0f,%.0f,%.0f) vtable=0x%X" % (pos[0],pos[1],pos[2],myvt))
cls=collections.Counter(); same=[]
for line in open("s800.txt"):
    hexv=line.strip()[2:]
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x4000], key=os.path.getmtime)
    if not fs: continue
    raw=open(fs[-1],"rb").read()
    vt=struct.unpack_from("<Q", raw, 0)[0]
    cls[vt]+=1
    if vt==myvt:
        p376=struct.unpack_from("<3f", raw, 0x376C)
        p978=struct.unpack_from("<3f", raw, 0x978)
        same.append((hexv,p376,p978,float(np.linalg.norm(np.array(p376)-pos)) if np.isfinite(p376).all() else -1))
print("classes seen:", len(cls))
for vt,c in cls.most_common(5): print("   0x%X -> %d" % (vt,c))
print("\nsame-class instances: %d" % len(same))
same.sort(key=lambda x:x[3])
for v,a,b,d in same[:12]:
    print("   0x%-10s 376C=(%9.1f,%9.1f,%9.1f) d=%7.0f   978=(%.0f,%.0f,%.0f)" % (v,a[0],a[1],a[2],d,b[0],b[1],b[2]))
