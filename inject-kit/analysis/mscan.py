import numpy as np, glob, os, struct, time
def feed():
    for _ in range(40):
        raw=open(r"C:\ProgramData\sc_feed.bin","rb").read()
        if len(raw)>=64 and struct.unpack_from("<I",raw,48)[0]:
            cam=np.array(struct.unpack_from("<3f",raw,8))
            if np.isfinite(cam).all() and abs(cam).sum()>1: return cam
        time.sleep(0.1)
cam=feed(); print("cam=",["%.1f"%v for v in cam])
fs=[f for f in glob.glob(r"C:\ProgramData\scdump\*_h*.bin") if os.path.getsize(f)>0x100000]
print("heap files:", len(fs))
hits=[]
for f in fs:
    a=np.fromfile(f,dtype=np.float32)
    n=(len(a)//16)*16
    if n < 16: continue
    m=a[:n].reshape(-1,16)
    # candidate: last row ~ (0,0,0,1) OR translation in [12..14]
    t1 = m[:,12:15]
    d = np.sqrt(((t1-cam)**2).sum(axis=1))
    idx = np.nonzero(d<2500)[0]
    if len(idx)==0: continue
    for i in idx[:50]:
        mm=m[i]
        if not np.isfinite(mm).all(): continue
        with np.errstate(over="ignore",invalid="ignore"):
            r0,r1,r2 = mm[0:3], mm[4:7], mm[8:11]
            if not all(0.9<np.linalg.norm(r)<1.1 for r in (r0,r1,r2)): continue
        hits.append((os.path.basename(f), i*0x40, mm[12:15].copy(), float(d[i])))
    if len(hits)>40: break
print("matrix hits near camera:", len(hits))
for nm,off,t,d in hits[:10]:
    print("  %-22s +0x%06X t=(%9.1f,%9.1f,%9.1f) d=%.0f" % (nm,off,t[0],t[1],t[2],d))
