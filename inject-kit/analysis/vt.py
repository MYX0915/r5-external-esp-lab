import numpy as np, glob, os
fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_7FF779626000.bin") if os.path.getsize(p)>0x100000]
if not fs: print("no rdata"); raise SystemExit
raw=open(fs[0],"rb").read()
a=np.frombuffer(raw, dtype=np.uint64)
target=0x7FF776980000+0x209A0D0
idx=np.nonzero(a==target)[0]
print("rdata size: %.1f MB" % (len(raw)/1048576))
print("references to 0x%X : %d" % (target, len(idx)))
for i in idx[:10]:
    print("   rdata+0x%06X  (RVA 0x%X)" % (i*8, 0x2CA4000+i*8))
