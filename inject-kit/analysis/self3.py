import struct, glob, os, numpy as np
want=np.array([float(x) for x in open("selfpos.txt").read().split()])
fs=[f for f in glob.glob(r"C:\ProgramData\scdump\1[0-9]_*.bin") if os.path.getsize(f)==0x2000]
print("targets dumped:", len(fs))
found=[]
for f in fs:
    a=np.fromfile(f,dtype=np.float32)
    if len(a)<3: continue
    # sliding triples
    best=None
    for i in range(0, len(a)-3):
        v=a[i:i+3]
        if not np.isfinite(v).all(): continue
        d=float(np.linalg.norm(v-want))
        if best is None or d<best[0]: best=(d,i*4,v.copy())
    if best and best[0] < 5.0:
        found.append((os.path.basename(f), best))
for nm,(d,off,v) in found:
    print("   MATCH %-18s +0x%05X (%9.1f,%9.1f,%9.1f) d=%.2f" % (nm,off,v[0],v[1],v[2],d))
print("matches:", len(found))
