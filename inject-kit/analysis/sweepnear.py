import numpy as np, glob, os, struct
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
cam=np.array(struct.unpack_from("<3f",f,8))
print("cam=(%.0f,%.0f,%.0f)" % tuple(cam))
hits=[]
for line in open("cur.txt"):
    hexv=line.strip()[2:]
    fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x4000]
    if not fs: continue
    a=np.fromfile(max(fs,key=os.path.getmtime),dtype=np.float32)
    n=(len(a)//3)*3
    T=a[:n].reshape(-1,3)
    with np.errstate(invalid="ignore"):
        ok=np.isfinite(T).all(axis=1)
        mag=np.abs(T).max(axis=1)
        d=np.linalg.norm(T-cam,axis=1)
        m=ok&(mag>200)&(mag<40000)&(d>50)&(d<2500)
    idx=np.nonzero(m)[0]
    if len(idx):
        i=idx[0]
        hits.append((float(d[i]),hexv,int(i*12),T[i].copy()))
hits.sort()
print("objects containing a triple within 2500 units: %d" % len(hits))
for d,v,off,t in hits[:10]:
    print("   %6.0f 0x%-10s +0x%05X (%.0f,%.0f,%.0f)" % (d,v,off,t[0],t[1],t[2]))
