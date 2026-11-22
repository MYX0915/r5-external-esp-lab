import numpy as np, glob, os
insts=[l.strip() for l in open("all869.txt") if l.strip()]
best=[]
for v in insts:
    hexv=v[2:]
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x4000], key=os.path.getmtime)
    if len(fs)<2: continue
    a=np.fromfile(fs[-2],dtype=np.float32); b=np.fromfile(fs[-1],dtype=np.float32)
    n=min(len(a),len(b))//3*3
    A=a[:n].reshape(-1,3); B=b[:n].reshape(-1,3)
    with np.errstate(invalid="ignore"):
        D=np.abs(A-B)
        ws=(np.abs(A)>500).all(axis=1)&(np.abs(B)>500).all(axis=1)&(np.abs(A)<40000).all(axis=1)&(np.abs(B)<40000).all(axis=1)
        moved=(D>0.2).all(axis=1)&(D<2000).all(axis=1)
        indep=(np.abs(D[:,0]-D[:,1])>0.1)|(np.abs(D[:,1]-D[:,2])>0.1)
    m=ws&moved&indep
    idx=np.nonzero(m)[0]
    if len(idx):
        i=idx[0]
        best.append((len(idx), v, int(i*12), A[i].copy(), B[i].copy(), D[i].copy()))
best.sort(reverse=True)
print("entities with independent 3-float movement in world range: %d" % len(best))
for c,v,off,va,vb,dv in best[:8]:
    print("  %s n=%d at +0x%05X" % (v,c,off))
    print("      %s -> %s (d=%s)" % ("(%.1f,%.1f,%.1f)"%tuple(va), "(%.1f,%.1f,%.1f)"%tuple(vb), "(%.2f,%.2f,%.2f)"%tuple(dv)))
