import numpy as np, glob, os
fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_7FF7424115D8.bin") if os.path.getsize(p)==0x200000]
if not fs:
    fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_*.bin") if os.path.getsize(p)==0x200000]
    fs.sort(key=os.path.getmtime, reverse=True)
a=np.fromfile(fs[0], dtype=np.uint8)
q=a.view(np.uint64)[::4]
nz=np.nonzero(q)[0]
insts=[int(q[i]) for i in nz if i>100 and (int(q[i])>>47)==0 and int(q[i])>=0x10000]
open("allinst.txt","w").write("\n".join("0x%X"%v for v in insts))
print("????: %d" % len(insts))
