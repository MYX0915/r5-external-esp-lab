import numpy as np, glob, os, struct, time
def feed():
    for _ in range(40):
        raw=open(r"C:\ProgramData\sc_feed.bin","rb").read()
        if len(raw)>=68 and struct.unpack_from("<I",raw,64)[0]:
            cam=np.array(struct.unpack_from("<3f",raw,8)); pos=np.array(struct.unpack_from("<3f",raw,32))
            if np.isfinite(pos).all() and np.abs(pos).sum()>1: return cam,pos
        time.sleep(0.1)
cam,pos=feed()
print("player pos=",["%.1f"%v for v in pos])
fs=[f for f in glob.glob(r"C:\ProgramData\scdump\1*_h*.bin") if os.path.getsize(f)>0x100000]
print("heap files:", len(fs))
def scan(a, near, radius=400):
    best=None
    for stride in (0x30,):
        n=(len(a)*4 - stride*8)//4
        for off in range(0, n*4, stride):
            i=off//4
            m=a[i:i+12]
            if len(m)<12 or not np.isfinite(m).all(): continue
            t=np.array([m[3],m[7],m[11]])
            d=float(np.linalg.norm(t-near))
            if d>radius: continue
            # check orthonormal-ish
            with np.errstate(over="ignore",invalid="ignore"):
                ok=True
                for r in (m[0:3],m[4:7],m[8:11]):
                    nn=float(np.linalg.norm(r))
                    if not (0.9<nn<1.1): ok=False; break
            if ok: return (off, t, d)
    return None
found=[]
for f in fs:
    a=np.fromfile(f,dtype=np.float32)
    r=scan(a,pos)
    if r: found.append((os.path.basename(f), r))
    if len(found)>=5: break
print("hits:", len(found))
for nm,(off,t,d) in found:
    print("  %-22s +0x%06X t=(%9.1f,%9.1f,%9.1f) dist=%.1f" % (nm,off,t[0],t[1],t[2],d))
