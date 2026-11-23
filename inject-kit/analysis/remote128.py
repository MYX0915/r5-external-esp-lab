import numpy as np, glob, os, struct
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
me=np.array(struct.unpack_from("<3f",f,32))
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_11FEB5B30.bin") if os.path.getsize(p)==0x20000], key=os.path.getmtime)
if not fs: print("no 128KB dump"); raise SystemExit
a=np.fromfile(fs[-1],dtype=np.float32)
n=(len(a)//3)*3
T=a[:n].reshape(-1,3)
with np.errstate(invalid="ignore"):
    ok=np.isfinite(T).all(axis=1)
    x,y,z=T[:,0],T[:,1],T[:,2]
    m=ok&(np.abs(x)>1000)&(np.abs(x)<35000)&(np.abs(y)>1000)&(np.abs(y)<35000)&(np.abs(z)<6000)
idx=np.nonzero(m)[0]
print("128KB ??????????: %d" % len(idx))
for i in idx[:12]:
    d=float(np.linalg.norm(T[i]-me))
    print("   +0x%05X (%.1f, %.1f, %.1f)  d=%.0f" % (i*12, T[i][0],T[i][1],T[i][2], d))
# ??? +0x376C ??
for off in (0x376C,0x378,0x97C,0x16C,0x17C):
    t=struct.unpack_from("<3f", open(fs[-1],"rb").read(), off)
    print("   +0x%04X = (%.1f, %.1f, %.1f)" % (off,t[0],t[1],t[2]))
