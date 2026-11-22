import numpy as np, glob, os, re
A={}; B={}
for p in glob.glob(r"C:\ProgramData\scdump\100_h*.bin"):
    m=re.search(r"100_(h\d+_[0-9A-F]+)\.bin", os.path.basename(p))
    if m: A[m.group(1)]=p
for p in glob.glob(r"C:\ProgramData\scdump\101_h*.bin"):
    m=re.search(r"101_(h\d+_[0-9A-F]+)\.bin", os.path.basename(p))
    if m: B[m.group(1)]=p
print("regions:", len(set(A)&set(B)))
found=[]; total=0
for k in sorted(set(A)&set(B)):
    a=np.fromfile(A[k],dtype=np.float32); b=np.fromfile(B[k],dtype=np.float32)
    n=min(len(a),len(b)); n3=(n//3)*3
    a=a[:n3].reshape(-1,3); b=b[:n3].reshape(-1,3)
    ok=np.isfinite(a).all(axis=1)&np.isfinite(b).all(axis=1)
    world=lambda m: (np.abs(m[:,0])>500)&(np.abs(m[:,0])<40000)&(np.abs(m[:,1])<40000)&(np.abs(m[:,2])<40000)
    d=np.abs(a-b).max(axis=1)
    m2=ok&world(a)&world(b)&(d>0.3)&(d<3000)
    idx=np.nonzero(m2)[0]
    total+=len(idx)
    if len(idx):
        found.append((len(idx),k,a[idx[0]].copy(),b[idx[0]].copy(),int(idx[0]*12)))
found.sort(reverse=True)
print("total moving world triples:", total)
for c,k,va,vb,off in found[:10]:
    print("   %-22s n=%-4d +0x%06X  (%.1f,%.1f,%.1f) -> (%.1f,%.1f,%.1f)" % (k,c,off,va[0],va[1],va[2],vb[0],vb[1],vb[2]))
