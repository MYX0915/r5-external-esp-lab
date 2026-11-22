import numpy as np, glob, os
fs=[f for f in glob.glob(r"C:\ProgramData\scdump\2_*.bin") if os.path.getsize(f)>0x100]
print("dumps:", len(fs))
for f in fs[:10]:
    a=np.fromfile(f,dtype=np.float32)
    n=len(a); hits=[]
    for i in range(0,n-3):
        v=a[i:i+3]
        if not np.isfinite(v).all(): continue
        if max(abs(v[0]),abs(v[1]),abs(v[2]))>9000: continue
        if min(abs(v[0]),abs(v[1]),abs(v[2]))<0.5: continue
        if len(set(np.round(v,1)))<3: continue
        hits.append((i*4, v.copy()))
        if len(hits)>=3: break
    print(" ", os.path.basename(f), "candidates:", len(hits))
    for off,v in hits:
        print("      +0x%05X (%9.2f,%9.2f,%9.2f)" % (off,v[0],v[1],v[2]))
