import numpy as np, glob, os, struct
target = 0xC1A10000 + 0x14CFFA0
print("bone array VA = 0x%X" % target)
tgt=np.uint64(target)
for f in sorted(glob.glob(r"C:\ProgramData\scdump\*_h*.bin"))[:24]:
    if os.path.getsize(f) < 0x100000: continue
    a=np.fromfile(f,dtype=np.uint64)
    idx=np.nonzero(a==tgt)[0]
    if len(idx):
        print("   %-24s refs=%d at %s" % (os.path.basename(f), len(idx), [hex(int(i*8)) for i in idx[:5]]))
