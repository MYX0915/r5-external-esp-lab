import numpy as np
a=np.fromfile(r"C:\ProgramData\scdump\9_1C10D7110.bin",dtype=np.float32)
b=np.fromfile(r"C:\ProgramData\scdump\10_1C10D7110.bin",dtype=np.float32)
n=min(len(a),len(b)); a=a[:n]; b=b[:n]
ch=np.nonzero(a!=b)[0]
print("changed float slots:", len(ch))
# group consecutive changed indices
groups=[]; s=ch[0]; p=ch[0]
for i in ch[1:]:
    if i==p+1: p=i; continue
    groups.append((s,p)); s=i; p=i
groups.append((s,p))
print("groups:", len(groups))
for s,e in groups:
    if e-s<2: continue
    offs=s*4
    va=a[s:e+1]; vb=b[s:e+1]
    if not (np.isfinite(va).all() and np.isfinite(vb).all()): continue
    if np.abs(va).max()>20000 or np.abs(vb).max()>20000: continue
    print("  +0x%04X..0x%04X  A=%s  B=%s" % (offs,(e+1)*4,
        " ".join("%.2f"%v for v in va[:6]), " ".join("%.2f"%v for v in vb[:6])))
