import numpy as np, glob, os, struct
for h,name in (("3AF1AAE0","???1(0.9m)"),("4037C280","???2(19.5m)")):
    A=sorted(glob.glob(r"C:\ProgramData\near_ref\*_%s.bin"%h))[0]
    Bs=sorted(glob.glob(r"C:\ProgramData\far_ref\*_%s.bin"%h))
    if not Bs: print(name,"? B ?"); continue
    a=np.fromfile(A,dtype=np.float32); b=np.fromfile(Bs[0],dtype=np.float32)
    n=min(len(a),len(b)); a=a[:n]; b=b[:n]
    print("\n=== %s ===  ????=%d  ????=%d" % (name,int((a!=0).sum()),int((b!=0).sum())))
    with np.errstate(invalid="ignore",over="ignore"):
        d=np.abs(a-b)
    m=np.isfinite(d)&(d>1e-4)
    idx=np.nonzero(m)[0]
    # ?????????? tick ??
    keep=[i for i in idx if not (abs(a[i])>1000 and abs(b[i])>1000 and abs(a[i]-b[i])<50)]
    print("   ????: %d (??tick? %d)" % (len(idx),len(keep)))
    for i in keep[:20]:
        print("      +0x%05X  ?=%12.6g   ?=%12.6g" % (i*4,a[i],b[i]))
