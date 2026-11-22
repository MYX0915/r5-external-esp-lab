import numpy as np, glob, os
lo=0x2493C0000000; hi=lo+0x40000000
files=[p for p in glob.glob(r"C:\ProgramData\scdump\10*_h*.bin")]
print("files:", len(files))
hits=[]
for p in files:
    a=np.fromfile(p,dtype=np.uint64)
    m=(a>=lo)&(a<hi)
    idx=np.nonzero(m)[0]
    if len(idx): hits.append((os.path.basename(p), len(idx), int(a[idx[0]]), int(idx[0]*8)))
print("qwords in pool range:", len(hits))
for nm,c,v,off in hits[:8]:
    print("   %-22s count=%-4d first=0x%X at +0x%X" % (nm,c,v,off))
