import numpy as np, glob, os, re
def pairs(preA, preB):
    A={}; B={}
    for p in glob.glob(r"C:\ProgramData\scdump\%d_h*.bin"%preA):
        m=re.search(r"%d_(h\d+_[0-9A-F]+)\.bin"%preA, os.path.basename(p))
        if m: A[m.group(1)]=p
    for p in glob.glob(r"C:\ProgramData\scdump\%d_h*.bin"%preB):
        m=re.search(r"%d_(h\d+_[0-9A-F]+)\.bin"%preB, os.path.basename(p))
        if m: B[m.group(1)]=p
    return A,B
A,B=pairs(96,97)
print("regions:", len(set(A)&set(B)))
found=[]
for k in sorted(set(A)&set(B)):
    a=np.fromfile(A[k],dtype=np.float32); b=np.fromfile(B[k],dtype=np.float32)
    n=min(len(a),len(b)); a=a[:n]; b=b[:n]
    n3=(n//3)*3
    a=a[:n3].reshape(-1,3); b=b[:n3].reshape(-1,3)
    ok=np.isfinite(a).all(axis=1)&np.isfinite(b).all(axis=1)
    world=lambda m: (np.abs(m[:,0])>500)&(np.abs(m[:,0])<40000)&(np.abs(m[:,1])<40000)&(np.abs(m[:,2])<40000)
    m=ok&world(a)&world(b)
    d=np.abs(a-b).max(axis=1)
    m2=m&(d>0.3)&(d<5000)
    idx=np.nonzero(m2)[0]
    if len(idx):
        found.append((len(idx),k,a[idx[0]].copy(),b[idx[0]].copy(),int(idx[0]*12)))
found.sort(reverse=True)
print("regions with moving world-space triples:", len(found))
for c,k,va,vb,off in found[:8]:
    print("   %-22s n=%-4d at +0x%06X  %s -> %s" % (k,c,off,
          "(%.1f,%.1f,%.1f)"%tuple(va), "(%.1f,%.1f,%.1f)"%tuple(vb)))
