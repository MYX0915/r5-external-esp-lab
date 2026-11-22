import numpy as np, glob, os
for f in sorted(glob.glob(r"C:\ProgramData\scdump\10_*.bin"))+sorted(glob.glob(r"C:\ProgramData\scdump\11_*.bin")):
    if os.path.getsize(f)<0x100: continue
    a=np.fromfile(f,dtype=np.float32)
    hits=[]
    for i in range(0,len(a)-3):
        v=a[i:i+3]
        if not np.isfinite(v).all(): continue
        if max(abs(v[0]),abs(v[1]),abs(v[2]))>9000: continue
        if min(abs(v[0]),abs(v[1]),abs(v[2]))<0.5: continue
        if len(set(np.round(v,1)))<3: continue
        hits.append((i*4,v.copy()))
        if len(hits)>=2: break
    if hits:
        print("%s:" % os.path.basename(f))
        for off,v in hits:
            print("    +0x%05X (%9.2f,%9.2f,%9.2f)" % (off,v[0],v[1],v[2]))
