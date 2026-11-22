import numpy as np, glob, os
arr=[p for p in glob.glob(r"C:\ProgramData\scdump\*_7FF77D4D15D8.bin") if os.path.getsize(p)==0x200000]
a=np.fromfile(max(arr,key=os.path.getmtime), dtype=np.uint8)
q=a.view(np.uint64)[::4]
nz=np.nonzero(q)[0]
insts=[int(q[i]) for i in nz if i>5 and (int(q[i])>>47)==0 and int(q[i])>=0x10000]
print("total instances:", len(insts))
# spread sample
import math
k=math.ceil(len(insts)/40)
sample=insts[::k][:40]
open("spread40.txt","w").write("\n".join("0x%X 0x4000"%v for v in sample))
print("sampled:", len(sample))
