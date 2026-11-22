import numpy as np, glob, os, struct, time
def feed():
    for _ in range(40):
        raw=open(r"C:\ProgramData\sc_feed.bin","rb").read()
        if len(raw)>=68 and struct.unpack_from("<I",raw,64)[0]:
            cam=np.array(struct.unpack_from("<3f",raw,8)); pos=np.array(struct.unpack_from("<3f",raw,32))
            if np.isfinite(pos).all() and np.abs(pos).sum()>1: return cam,pos
        time.sleep(0.1)
cam,pos=feed(); print("player pos=",["%.1f"%v for v in pos])
fs=sorted([f for f in glob.glob(r"C:\ProgramData\scdump\1*_h*.bin") if os.path.getsize(f)>0x100000])
print("heap files:", len(fs))
CX,CY,CZ = pos
for f in fs:
    a=np.fromfile(f,dtype=np.float32)
    n=(len(a)//12)*12
    if n < 12: continue
    m=a[:n].reshape(-1,12)
    t=m[:, [3,7,11]]
    d=np.sqrt(((t-np.array(pos))**2).sum(axis=1))
    idx=np.nonzero(d<400)[0]
    if len(idx)==0: continue
    # orthonormality filter
    keep=[]
    for i in idx:
        rows=[m[i,0:3], m[i,4:7], m[i,8:11]]
        if not np.isfinite(rows).all(): continue
        ok=all(0.9<np.linalg.norm(r)<1.1 for r in rows)
        if ok: keep.append(i)
    if keep:
        print("%-22s stride0x30 candidates=%d  (dist<400)" % (os.path.basename(f), len(keep)))
        for i in keep[:3]:
            print("     +0x%06X t=(%9.1f,%9.1f,%9.1f) d=%.1f" % (i*0x30, *m[i,[3,7,11]], d[i]))
