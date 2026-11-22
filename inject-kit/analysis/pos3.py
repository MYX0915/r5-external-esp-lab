import numpy as np, glob, os
D=r"C:\ProgramData\scdump"
files=sorted(glob.glob(os.path.join(D,"7_*.bin")))
data={}
for f in files:
    va=int(os.path.basename(f).split("_")[1].split(".")[0],16)
    data[va]=np.fromfile(f,dtype=np.float32)
ks=sorted(data); a,b,c=data[ks[0]],data[ks[1]],data[ks[2]]
n=min(len(a),len(b),len(c))
found=[]
for i in range(0,n-3):
    v1,v2,v3=a[i:i+3],b[i:i+3],c[i:i+3]
    if not (np.isfinite(v1).all() and np.isfinite(v2).all() and np.isfinite(v3).all()): continue
    if max(np.abs(v1).max(),np.abs(v2).max(),np.abs(v3).max())>20000: continue
    nz1=int((np.abs(v1)>0.5).sum())
    if nz1<2: continue
    # entities stand apart -> at least two of them differ
    d12=not np.allclose(v1,v2); d13=not np.allclose(v1,v3)
    if not (d12 and d13): continue
    found.append((i*4, v1.copy(), v2.copy(), v3.copy()))
print("candidates:", len(found))
for off,v1,v2,v3 in found[:25]:
    print("  0x%05X A=(%8.1f,%8.1f,%8.1f) B=(%8.1f,%8.1f,%8.1f) C=(%8.1f,%8.1f,%8.1f)" % (off,*v1,*v2,*v3))
