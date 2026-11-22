import numpy as np, glob, os
D=r"C:\ProgramData\scdump"
files=sorted(glob.glob(os.path.join(D,"13_*.bin")))
data=[]
for f in files:
    va=int(os.path.basename(f).split("_")[1].split(".")[0],16)
    data.append((va, np.fromfile(f,dtype=np.float32)))
n=min(len(d) for _,d in data)
# score each offset: how many entities have a plausible vec3 there
score=np.zeros(n, dtype=np.int32)
for va,a in data:
    w=a[:n]
    ok=np.zeros(n,dtype=bool)
    x,y,z=w[:-2],w[1:-1],w[2:]
    ok[:-2] = (np.isfinite(x)&np.isfinite(y)&np.isfinite(z) &
               (np.abs(x)<9000)&(np.abs(y)<9000)&(np.abs(z)<2000) &
               ((np.abs(x)>1)|(np.abs(y)>1)))
    score += ok.astype(np.int32)
best=np.argsort(-score)[:12]
print("offsets where most entities look like a world vec3:")
for i in best:
    if score[i]<8: break
    print("  +0x%05X  %d/%d entities" % (i*4, score[i], len(data)))
    for va,a in data[:3]:
        v=a[i:i+3]
        print("       0x%-11X (%9.2f,%9.2f,%9.2f)" % (va, v[0],v[1],v[2]))
