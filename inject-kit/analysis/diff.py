import numpy as np, glob, os, re, collections
def load(p):
    return np.fromfile(p, dtype=np.uint64)
# pair passes by region name
A={}; B={}
for p in glob.glob(r"C:\ProgramData\scdump\89_h*.bin"):
    m=re.search(r"89_(h\d+_[0-9A-F]+)\.bin", os.path.basename(p))
    if m: A[m.group(1)]=p
for p in glob.glob(r"C:\ProgramData\scdump\90_h*.bin"):
    m=re.search(r"90_(h\d+_[0-9A-F]+)\.bin", os.path.basename(p))
    if m: B[m.group(1)]=p
common=sorted(set(A)&set(B))
print("paired regions:", len(common))
tot=0; changed=collections.Counter()
samples=[]
for k in common:
    a=load(A[k]); b=load(B[k])
    n=min(len(a),len(b))
    a=a[:n]; b=b[:n]
    ta=(a>>59)&0x1F; tb=(b>>59)&0x1F
    fa=(a&0xFFFFFFFF).astype(np.uint32).view(np.float32)
    fb=(b&0xFFFFFFFF).astype(np.uint32).view(np.float32)
    m=(ta==4)&(tb==4)&np.isfinite(fa)&np.isfinite(fb)&(fa!=fb)&(np.abs(fa)>1)&(np.abs(fb)>1)&(np.abs(fa)<20000)&(np.abs(fb)<20000)
    c=int(m.sum()); changed[k]=c; tot+=c
    if c and len(samples)<8:
        idx=np.nonzero(m)[0][:4]
        samples.append((k,[ (hex(int(i*8)), float(fa[i]), float(fb[i])) for i in idx ]))
print("total changed tagged floats:", tot)
for k,c in changed.most_common(6):
    print("   %-22s changed=%d" % (k,c))
for k,s in samples[:4]:
    print("   %s: %s" % (k,s))
