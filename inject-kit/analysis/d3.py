import numpy as np, glob, os
fs=[f for f in glob.glob(r"C:\ProgramData\scdump\13_*.bin") if os.path.getsize(f)>0x10000]
print("dumped:", len(fs), [os.path.getsize(f) for f in fs][:3])
for f in fs:
    a=np.fromfile(f,dtype=np.float32)
    hits=[]
    for i in range(0,len(a)-3):
        v=a[i:i+3]
        if not np.isfinite(v).all(): continue
        if max(abs(v[0]),abs(v[1]),abs(v[2]))>9000: continue
        if min(abs(v[0]),abs(v[1]),abs(v[2]))<0.5: continue
        if len(set(np.round(v,1)))<3: continue
        hits.append((i*4,v.copy()))
    print("%-20s hits=%d %s" % (os.path.basename(f), len(hits), " ".join("+0x%X"%h[0] for h in hits[:6])))
    for off,v in hits[:2]:
        print("      +0x%05X (%9.2f,%9.2f,%9.2f)" % (off,v[0],v[1],v[2]))
