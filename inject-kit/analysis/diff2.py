import numpy as np, glob, os, re, collections
A={}; B={}
for p in glob.glob(r"C:\ProgramData\scdump\96_h*.bin"):
    m=re.search(r"96_(h\d+_[0-9A-F]+)\.bin", os.path.basename(p))
    if m: A[m.group(1)]=p
for p in glob.glob(r"C:\ProgramData\scdump\97_h*.bin"):
    m=re.search(r"97_(h\d+_[0-9A-F]+)\.bin", os.path.basename(p))
    if m: B[m.group(1)]=p
common=sorted(set(A)&set(B))
print("paired regions:", len(common))
res=[]
for k in common:
    a=np.fromfile(A[k],dtype=np.uint64); b=np.fromfile(B[k],dtype=np.uint64)
    n=min(len(a),len(b)); a=a[:n]; b=b[:n]
    fa=(a&0xFFFFFFFF).astype(np.uint32).view(np.float32)
    fb=(b&0xFFFFFFFF).astype(np.uint32).view(np.float32)
    ok=np.isfinite(fa)&np.isfinite(fb)&(np.abs(fa)>1)&(np.abs(fb)>1)&(np.abs(fa)<20000)&(np.abs(fb)<20000)
    df=np.abs(fa-fb)
    m=ok&(df>0.05)
    c=int(m.sum())
    if c:
        idx=np.nonzero(m)[0]
        res.append((c,k,[(hex(int(i*8)),float(fa[i]),float(fb[i])) for i in idx[:4]]))
res.sort(reverse=True)
print("regions with changing float32 values:", len(res))
for c,k,s in res[:8]:
    print("   %-22s changed=%-6d e.g. %s" % (k,c,s[:2]))
