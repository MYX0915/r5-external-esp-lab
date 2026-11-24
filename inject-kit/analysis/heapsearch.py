import numpy as np, glob, os, datetime
me=np.array((-7293.9, 1187.4, -20.0), dtype=np.float64)
# ????? dump ??
fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_h*.bin") if os.path.getsize(p)>0x100000]
fs.sort(key=os.path.getmtime, reverse=True)
print("??? %d ???? 8 ?:" % len(fs))
for p in fs[:8]:
    print("   %-24s %5.1f MB  %s" % (os.path.basename(p), os.path.getsize(p)/1048576,
          datetime.datetime.fromtimestamp(os.path.getmtime(p)).strftime('%H:%M:%S')))
hits=[]
for p in fs[:20]:
    a=np.fromfile(p, dtype=np.float32)
    n=len(a)//3*3
    T=a[:n].reshape(-1,3).astype(np.float64)
    with np.errstate(invalid="ignore",over="ignore"):
        d=np.linalg.norm(T-me, axis=1)
        m=np.isfinite(d)&(d<200)     # 3.8 ??
    for i in np.nonzero(m)[0]:
        hits.append((float(d[i]), os.path.basename(p), int(i)*4))
hits.sort()
print("\n?????? <3.8m ???????: %d ?" % len(hits))
for d,f,off in hits[:25]:
    print("   %5.2f m  %-22s +0x%06X" % (d*0.01905, f, off))
