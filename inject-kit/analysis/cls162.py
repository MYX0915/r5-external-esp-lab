import numpy as np, glob, os, struct
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
cam=np.array(struct.unpack_from("<3f",f,8))
print("cam=(%.0f,%.0f,%.0f)" % tuple(cam))
cands=[]
for line in open("cur.txt"):
    hexv=line.strip()[2:]
    fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x4000]
    if not fs: continue
    raw=open(max(fs,key=os.path.getmtime),"rb").read()
    vt=struct.unpack_from("<Q", raw, 0)[0]
    if vt==0x7FF779A60EF8: cands.append((hexv,fs[-1]))
print("class instances sampled: %d" % len(cands))
for hexv,path in cands[:3]:
    a=np.fromfile(path,dtype=np.float32)
    n=(len(a)//3)*3
    T=a[:n].reshape(-1,3)
    ok=np.isfinite(T).all(axis=1)
    d=np.linalg.norm(T-cam,axis=1)
    m=ok&(d<4000)&(np.abs(T).max(axis=1)<40000)
    idx=np.nonzero(m)[0]
    print("  0x%s: plausible triples=%d" % (hexv,len(idx)))
    for i in idx[:3]:
        print("      +0x%05X (%.0f,%.0f,%.0f) dist=%.0f" % (i*12,T[i][0],T[i][1],T[i][2],d[i]))
