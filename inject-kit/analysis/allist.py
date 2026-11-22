import numpy as np, glob, os
fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_7FF77D4D15D8.bin") if os.path.getsize(p)==0x200000]
a=np.fromfile(max(fs,key=os.path.getmtime), dtype=np.uint8)
q=a.view(np.uint64)[::4]
nz=np.nonzero(q)[0]
insts=[int(q[i]) for i in nz if i>100 and (int(q[i])>>47)==0 and int(q[i])>=0x10000]
open("all869.txt","w").write("\n".join("0x%X"%v for v in insts))
print("entities:", len(insts))
