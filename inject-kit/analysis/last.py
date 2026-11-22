import numpy as np, glob, os, struct, time
def feed():
    for _ in range(40):
        raw=open(r"C:\ProgramData\sc_feed.bin","rb").read()
        if len(raw)>=68 and struct.unpack_from("<I",raw,64)[0]:
            cam=np.array(struct.unpack_from("<3f",raw,8))
            if np.isfinite(cam).all() and abs(cam).sum()>1: return cam
        time.sleep(0.1)
cam=feed(); print("cam=",["%.1f"%v for v in cam])
for f in sorted(glob.glob(r"C:\ProgramData\scdump\17_*.bin")):
    if os.path.getsize(f)<0x1000: continue
    a=np.fromfile(f,dtype=np.float32)
    best=[]
    for i in range(0,len(a)-3):
        v=a[i:i+3]
        if not np.isfinite(v).all(): continue
        nz=int((np.abs(v)>0.5).sum())
        if nz<2: continue
        if np.abs(v).max()>12000: continue
        d=float(np.linalg.norm(v-cam))
        if d<3000: best.append((d,i*4,v.copy()))
    best.sort()
    print("%-20s candidates=%d" % (os.path.basename(f), len(best)))
    for d,off,v in best[:3]:
        print("     +0x%05X (%9.1f,%9.1f,%9.1f) dist=%.1f" % (off,v[0],v[1],v[2],d))
