import numpy as np, glob, os, struct
files=sorted(glob.glob(r"C:\ProgramData\scA2\*.bin"))
print("A ???: %d ?" % len(files))
hits=[]
for p in files:
    a=np.fromfile(p, dtype=np.float32)
    n=(len(a)//3)*3
    if n<3: continue
    T=a[:n].reshape(-1,3)
    with np.errstate(invalid="ignore"):
        m=np.isfinite(T).all(axis=1)&(T[:,0]>0.5)&(T[:,0]<=1.01)&(np.abs(T[:,1])<0.05)&(np.abs(T[:,2])<0.05)
    idx=np.nonzero(m)[0]
    if len(idx):
        name=os.path.basename(p)
        hits.append((name, idx[:4].tolist(), T[idx[0]].tolist()))
print("???(1,0,0)???????: %d" % len(hits))
for nm,offs,val in hits[:15]:
    print("   %-22s ??=%s ?=%s" % (nm, [hex(o*4) for o in offs], ["%.2f"%v for v in val]))
