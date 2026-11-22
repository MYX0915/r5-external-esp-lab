import numpy as np, glob, os
D=r"C:\ProgramData\scdump"
files=sorted(glob.glob(os.path.join(D,"7_*.bin")))
print("files:", len(files))
data={}
for f in files:
    va=int(os.path.basename(f).split("_")[1].split(".")[0],16)
    data[va]=np.fromfile(f,dtype=np.float32)
va0=sorted(data)[0]
a=data[sorted(data)[0]]; b=data[sorted(data)[1]]; c=data[sorted(data)[2]]
n=min(len(a),len(b),len(c))
found=[]
for i in range(0,n-3):
    v1,v2,v3=a[i:i+3],b[i:i+3],c[i:i+3]
    if not (np.isfinite(v1).all() and np.isfinite(v2).all() and np.isfinite(v3).all()): continue
    if np.abs(v1).max()>8000 or np.abs(v2).max()>8000 or np.abs(v3).max()>8000: continue
    if np.abs(v1).min()<1: continue
    if len(set(np.round(v1,2)))<3: continue
    if np.allclose(v1,v2) and np.allclose(v2,v3): continue
    found.append((i*4, v1.copy(), v2.copy(), v3.copy()))
print("candidate Vec3 offsets:", len(found))
for off,v1,v2,v3 in found[:20]:
    print("  0x%05X  A=(%9.2f,%9.2f,%9.2f)  B=(%9.2f,%9.2f,%9.2f)  C=(%9.2f,%9.2f,%9.2f)" %
          (off, *v1, *v2, *v3))
