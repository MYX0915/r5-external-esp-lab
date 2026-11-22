import numpy as np, glob, os
for f in sorted(glob.glob(r"C:\ProgramData\scdump\6_*.bin")):
    a=np.fromfile(f,dtype=np.float32)
    hits=[]
    for i in range(0,len(a)-3):
        v=a[i:i+3]
        if not np.isfinite(v).all(): continue
        if max(abs(v[0]),abs(v[1]),abs(v[2]))>9000: continue
        if min(abs(v[0]),abs(v[1]),abs(v[2]))<0.5: continue
        if len(set(np.round(v,2)))<3: continue
        hits.append((i*4,v.copy()))
        if len(hits)>=4: break
    print("%s  candidates=%d" % (os.path.basename(f), len(hits)))
    for off,v in hits:
        print("     +0x%05X (%9.2f,%9.2f,%9.2f)" % (off,v[0],v[1],v[2]))
