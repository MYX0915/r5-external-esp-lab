import numpy as np, glob, os, struct
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
cam=np.array(struct.unpack_from("<3f",f,8))
print("cam=(%.0f,%.0f,%.0f)" % tuple(cam))
out=[]
for line in open("cur.txt"):
    hexv=line.strip()[2:]
    fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x4000]
    if not fs: continue
    a=np.fromfile(max(fs,key=os.path.getmtime),dtype=np.float32)
    n=(len(a)//3)*3
    T=a[:n].reshape(-1,3)
    with np.errstate(invalid="ignore"):
        ok=np.isfinite(T).all(axis=1)
        x=T[:,0]; y=T[:,1]; z=T[:,2]
        m=ok&(np.abs(x)>300)&(np.abs(x)<40000)&(np.abs(y)>300)&(np.abs(y)<40000)&(np.abs(z)<5000)
        d=np.linalg.norm(T-cam,axis=1)
    idx=np.nonzero(m)[0]
    if len(idx):
        i=idx[0]
        out.append((float(d[i]),hexv,int(i*12),T[i].copy()))
out.sort()
print("objects with a 3-axis world-like triple: %d" % len(out))
for d,v,off,t in out[:10]:
    print("   %7.0f 0x%-10s +0x%05X (%.0f,%.0f,%.0f)" % (d,v,off,t[0],t[1],t[2]))
