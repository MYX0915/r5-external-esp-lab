import numpy as np
arr=np.fromfile(r"C:\ProgramData\scdump\1_7FF776981000.bin", dtype=np.uint8)
q=arr.view(np.uint64)[::4]
nz=np.nonzero(q)[0]
insts=[int(q[i]) for i in nz if i>100 and (int(q[i])>>47)==0 and int(q[i])>=0x10000]
print("instances:", len(insts))
import os
os.makedirs("vb", exist_ok=True)
for k in range(0, len(insts), 100):
    open("vb/v%03d.txt"%k,"w").write("\n".join("0x%X 0x200"%v for v in insts[k:k+100]))
print("batches:", len(os.listdir("vb")))
