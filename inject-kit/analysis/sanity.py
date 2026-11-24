import numpy as np, glob, os
a="0x3AF1AAE0"; hexv=a[2:]
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x2000], key=os.path.getmtime)[-15:]
print("???: %d" % len(fs))
for p in fs[:6]:
    d=np.fromfile(p,dtype=np.float32)
    nz=int((np.abs(d)>1e-6).sum())
    print("   %-24s ???? %5d / %d  ?? %s" % (os.path.basename(p), nz, len(d),
          __import__('datetime').datetime.fromtimestamp(os.path.getmtime(p)).strftime('%H:%M:%S')))
