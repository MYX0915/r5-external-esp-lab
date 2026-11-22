import numpy as np, glob, os
fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_7FF779624000.bin") if os.path.getsize(p)>0x100000]
if not fs: print("no rdata file"); raise SystemExit
raw=open(max(fs,key=os.path.getmtime),"rb").read()
a=np.frombuffer(raw, dtype=np.uint64)
target=0x7FF776980000+0x209A0D0
idx=np.nonzero(a==target)[0]
print("rdata %.1f MB, refs to 0x%X = %d" % (len(raw)/1048576, target, len(idx)))
for i in idx[:8]:
    print("   rdata+0x%06X (RVA 0x%X)" % (i*8, 0x2CA4000+i*8))
# also look for the other function
t2=0x7FF776980000+0x23FEB90
i2=np.nonzero(a==t2)[0]
print("refs to 0x23FEB90 =", len(i2))
for i in i2[:5]:
    print("   rdata+0x%06X (RVA 0x%X)" % (i*8, 0x2CA4000+i*8))
