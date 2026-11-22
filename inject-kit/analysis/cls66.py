import numpy as np, glob, os, struct
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
cam=np.array(struct.unpack_from("<3f",f,8))
tgt=0x7FF779ABEE60
objs=[]
for line in open("cur.txt"):
    hexv=line.strip()[2:]
    fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x4000]
    if not fs: continue
    raw=open(max(fs,key=os.path.getmtime),"rb").read()
    if struct.unpack_from("<Q", raw, 0)[0]==tgt: objs.append((hexv,max(fs,key=os.path.getmtime)))
print("class 0x%X objects: %d" % (tgt,len(objs)))
for hexv,path in objs[:4]:
    a=np.fromfile(path,dtype=np.float32); n=(len(a)//3)*3
    T=a[:n].reshape(-1,3)
    with np.errstate(invalid="ignore"):
        ok=np.isfinite(T).all(axis=1); mag=np.abs(T).max(axis=1)
        d=np.linalg.norm(T-cam,axis=1)
        m=ok&(mag>300)&(mag<40000)&(d<20000)
    idx=np.nonzero(m)[0]
    print("  0x%s triples=%d" % (hexv,len(idx)))
    for i in idx[:3]:
        print("      +0x%05X (%.0f,%.0f,%.0f) d=%.0f" % (i*12,T[i][0],T[i][1],T[i][2],d[i]))
