import numpy as np, glob, os
fs=[f for f in glob.glob(r"C:\ProgramData\scdump\*_h*.bin") if os.path.getsize(f)>0x100000]
print("heap files:", len(fs))
def scan(a, need=25, cluster=250.0):
    n=(len(a)//12)
    if n < need+1: return None
    m=a[:n*12].reshape(n,12)
    t=m[:, [3,7,11]]
    ok=np.isfinite(t).all(axis=1) & (np.abs(t).max(axis=1)<20000) & (np.abs(t).max(axis=1)>1)
    d=np.zeros(n)
    d[1:]=np.linalg.norm(np.diff(t,axis=0),axis=1)
    close = ok & (d<cluster)
    # find longest consecutive True run
    best=0; bestStart=-1; cur=0; start=0
    for i in range(1,n):
        if close[i]:
            if cur==0: start=i-1
            cur+=1
            if cur>best: best=cur; bestStart=start
        else:
            cur=0
    if best>=need: return (best, bestStart, t[bestStart:bestStart+3])
    return None
hits=[]
for f in fs:
    a=np.fromfile(f,dtype=np.float32)
    r=scan(a)
    if r:
        ln,st,t=r
        hits.append((ln, os.path.basename(f), st*0x30, t))
        print("   %-24s run=%-4d at +0x%06X  first t=(%9.1f,%9.1f,%9.1f)" % (os.path.basename(f),ln,st*0x30,t[0][0],t[0][1],t[0][2]))
print("hits:", len(hits))
