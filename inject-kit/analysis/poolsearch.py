import numpy as np, glob, os
lo=0x2493C0000000; hi=lo+0x10000000
print("searching heap for qwords in [0x%X, 0x%X) ..." % (lo,hi))
found=[]
for f in glob.glob(r"C:\ProgramData\scdump\*_h*.bin"):
    if os.path.getsize(f) < 0x100000: continue
    a=np.fromfile(f,dtype=np.uint64)
    m=(a>=lo)&(a<hi)
    idx=np.nonzero(m)[0]
    for i in idx[:5]:
        found.append((os.path.basename(f), int(i*8), int(a[i])))
    if len(found)>10: break
print("hits:", len(found))
for nm,off,v in found[:10]:
    print("   %-24s +0x%06X = 0x%X" % (nm, off, v))
