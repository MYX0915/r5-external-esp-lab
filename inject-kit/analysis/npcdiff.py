import numpy as np, glob, os
D=r"C:\ProgramData\scdump"
A={}; B={}
for f in glob.glob(os.path.join(D,"13_*.bin")):
    va=int(os.path.basename(f).split("_")[1].split(".")[0],16); A[va]=np.fromfile(f,dtype=np.float32)
for f in glob.glob(os.path.join(D,"14_*.bin")):
    va=int(os.path.basename(f).split("_")[1].split(".")[0],16); B[va]=np.fromfile(f,dtype=np.float32)
common=sorted(set(A)&set(B))
print("pairs:", len(common))
# for each 4-byte offset, count how many entities have a changed value there
n=min(len(A[common[0]]), len(B[common[0]]))
moved=np.zeros(n, dtype=np.int32)
for va in common:
    a=A[va][:n]; b=B[va][:n]
    moved += (a!=b).astype(np.int32)
# how many entities changed at each offset
score=np.argsort(-moved)[:40]
print("offsets changed in most entities:")
cnt=0
for i in score:
    if moved[i] < 3: break
    off=i*4
    vals=[]
    for va in common[:4]:
        va1=A[va][i]; vb1=B[va][i]
        vals.append("%.1f->%.1f" % (va1,vb1))
    print("  +0x%05X changed in %d/%d   e.g. %s" % (off, moved[i], len(common), " | ".join(vals)))
    cnt+=1
    if cnt>=15: break
