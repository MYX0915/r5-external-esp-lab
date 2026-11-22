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
hits=[]
for f in fs:
    a=np.fromfile(f,dtype=np.float32)
    for stride in (0x30, 0x40):
        n=(len(a)//(stride//4))*(stride//4)
        if n < 32: continue
        m=a[:n].reshape(-1, stride//4)
        # translation candidates: cols 3,7,11 (3x4 row-major) or 12,13,14 (4x4)
        cands = [(3,7,11), (12,13,14)]
        for cols in cands:
            if max(cols) >= m.shape[1]: continue
            t = m[:, list(cols)]
            with np.errstate(over="ignore", invalid="ignore"):
                d = np.sqrt(((t-cam)**2).sum(axis=1))
            idx = np.nonzero(np.isfinite(d) & (d<2500))[0]
            for i in idx[:40]:
                mm=m[i]
                if not np.isfinite(mm).all(): continue
                with np.errstate(over="ignore",invalid="ignore"):
                    rs=[mm[0:3], mm[4:7], mm[8:11]] if stride==0x30 else [mm[0:3], mm[4:7], mm[8:11]]
                    if not all(0.9<np.linalg.norm(r)<1.1 for r in rs): continue
                hits.append((os.path.basename(f), stride, i*stride, cols, mm[list(cols)].copy(), float(d[i])))
        if len(hits)>30: break
    if len(hits)>30: break
print("hits:", len(hits))
for nm,stride,off,cols,t,d in hits[:10]:
    print("  %-20s stride=0x%X +0x%06X cols=%s t=(%9.1f,%9.1f,%9.1f) d=%.0f" % (nm,stride,off,cols,t[0],t[1],t[2],d))
