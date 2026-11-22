import numpy as np, glob, os, struct, time
def feed():
    for _ in range(40):
        raw=open(r"C:\ProgramData\sc_feed.bin","rb").read()
        if len(raw)>=68 and struct.unpack_from("<I",raw,64)[0]:
            cam=np.array(struct.unpack_from("<3f",raw,8))
            if np.isfinite(cam).all() and abs(cam).sum()>1: return cam
        time.sleep(0.1)
cam=feed(); print("cam=",["%.1f"%v for v in cam])
files=[f for f in glob.glob(r"C:\ProgramData\scdump\2*_*.bin") if os.path.getsize(f)==0x3800]
print("objects to scan:", len(files))
near=[]
for f in files:
    raw=open(f,"rb").read()
    a=np.frombuffer(raw,dtype=np.float32)
    # 1) does it have a player-like origin at 0x376C?
    o=struct.unpack_from("<3f", raw, 0x376C)
    if np.isfinite(o).all() and np.linalg.norm(np.array(o)-cam) < 3000:
        near.append((os.path.basename(f), 0x376C, o, float(np.linalg.norm(np.array(o)-cam))))
    # 2) any triple near camera
    best=None
    for i in range(0,len(a)-3):
        v=a[i:i+3]
        if not np.isfinite(v).all(): continue
        if int((np.abs(v)>0.5).sum())<2: continue
        if np.abs(v).max()>12000: continue
        d=float(np.linalg.norm(v-cam))
        if d<800 and (best is None or d<best[0]): best=(d,i*4,v.copy())
    if best: near.append((os.path.basename(f), best[1], best[2], best[0]))
print("objects with a near-camera vec3:", len(near))
for nm,off,v,d in near[:15]:
    print("  %-20s +0x%05X (%9.1f,%9.1f,%9.1f) dist=%.1f" % (nm,off,v[0],v[1],v[2],d))
