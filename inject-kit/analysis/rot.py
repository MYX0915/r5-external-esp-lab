import numpy as np
a=np.fromfile(r"C:\ProgramData\scdump\10_1C10D7110.bin",dtype=np.float32)   # before rotate
b=np.fromfile(r"C:\ProgramData\scdump\11_1C10D7110.bin",dtype=np.float32)   # after rotate
n=min(len(a),len(b)); a=a[:n]; b=b[:n]
ch=np.nonzero(a!=b)[0]
print("changed float slots:", len(ch))
groups=[]; s=ch[0]; p=ch[0]
for i in ch[1:]:
    if i==p+1: p=i; continue
    groups.append((s,p)); s=i; p=i
groups.append((s,p))
print("groups:", len(groups))
for s,e in groups:
    va=a[s:e+1]; vb=b[s:e+1]
    if not (np.isfinite(va).all() and np.isfinite(vb).all()): continue
    if max(np.abs(va).max(),np.abs(vb).max())>1000: continue
    if e-s+1 > 8: 
        print("  +0x%04X (%d vals) A=%s B=%s" % (s*4, e-s+1,
            " ".join("%.2f"%v for v in va[:4]), " ".join("%.2f"%v for v in vb[:4])))
    else:
        print("  +0x%04X A=%s B=%s" % (s*4, " ".join("%.2f"%v for v in va), " ".join("%.2f"%v for v in vb)))
