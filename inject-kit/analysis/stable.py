import numpy as np, os
D=r"C:\ProgramData\scdump"
nm="12E5C6D00.bin"
a=np.fromfile(os.path.join(D,"4_"+nm),dtype=np.float32)
b=np.fromfile(os.path.join(D,"5_"+nm),dtype=np.float32)
n=min(len(a),len(b)); a=a[:n]; b=b[:n]
# stable non-zero scalars (candidates for the other two axes)
stable=[]
for i in range(n):
    v1,v2=a[i],b[i]
    if not (np.isfinite(v1) and np.isfinite(v2)): continue
    if abs(v1)>9000: continue
    if abs(v1)<0.5: continue
    if abs(v1-v2) > 0.01: continue      # unchanged
    stable.append((i*4, float(v1)))
print("stable non-zero scalars:", len(stable))
for off,v in stable[:25]:
    print("   +0x%05X  %10.3f" % (off,v))
print()
print("changed values:")
ch=np.nonzero(a!=b)[0]
for i in ch:
    v1,v2=float(a[i]),float(b[i])
    if not (np.isfinite(v1) and np.isfinite(v2)): continue
    if abs(v1)>9000 or abs(v2)>9000: continue
    print("   +0x%05X  %10.3f -> %10.3f" % (i*4,v1,v2))
