import numpy as np, glob, os, struct
myvt=int(open("vt2.txt").read(),16)
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
cam=np.array(struct.unpack_from("<3f",f,8))
print("my vtable=0x%X cam=(%.0f,%.0f,%.0f)" % (myvt,cam[0],cam[1],cam[2]))
same=[]
for line in open("m.txt"):
    hexv=line.strip()[2:]
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x4000], key=os.path.getmtime)
    if not fs: continue
    raw=open(fs[-1],"rb").read()
    if struct.unpack_from("<Q", raw, 0)[0]!=myvt: continue
    p376=struct.unpack_from("<3f", raw, 0x376C)
    p978=struct.unpack_from("<3f", raw, 0x978)
    same.append((hexv,p376,p978))
print("same-class instances: %d" % len(same))
for v,a,b in same[:15]:
    print("   0x%-10s 376C=(%8.1f,%8.1f,%8.1f)  978=(%8.1f,%8.1f,%8.1f)" % (v,a[0],a[1],a[2],b[0],b[1],b[2]))
