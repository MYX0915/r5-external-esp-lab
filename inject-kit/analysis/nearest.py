import numpy as np, glob, os, struct, math, time
def read_feed(tries=30):
    for _ in range(tries):
        raw=open(r"C:\ProgramData\sc_feed.bin","rb").read()
        if len(raw)>=68 and struct.unpack_from("<I",raw,64)[0]:
            cam=np.array(struct.unpack_from("<3f",raw,8))
            if np.isfinite(cam).all() and abs(cam).sum()>1: return cam
        time.sleep(0.1)
    return None
cam=read_feed()
print("cam=",["%.1f"%v for v in cam])
for f in sorted(glob.glob(r"C:\ProgramData\scdump\13_*.bin"))[:6]:
    if os.path.getsize(f)<0x1000: continue
    a=np.fromfile(f,dtype=np.float32)
    best=None
    for i in range(0,len(a)-3,4):
        v=a[i:i+3]
        if not np.isfinite(v).all(): continue
        if np.abs(v).max()>20000: continue
        d=float(np.linalg.norm(v-cam))
        if best is None or d<best[0]: best=(d,i*4,v.copy())
    if best:
        d,off,v=best
        print("%-20s closest +0x%05X (%9.1f,%9.1f,%9.1f) dist=%.1f" % (os.path.basename(f),off,v[0],v[1],v[2],d))
