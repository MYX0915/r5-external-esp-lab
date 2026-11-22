import numpy as np
arr=np.fromfile(r"C:\ProgramData\scdump\11_7FF68E8115D8.bin", dtype=np.uint8)
q=arr.view(np.uint64)[::4]
nz=np.nonzero(q)[0]
insts=[int(q[i]) for i in nz if i>100 and (int(q[i])>>47)==0 and int(q[i])>=0x10000]
print("instances:", len(insts))
# batches of 100, window 0x3800
import os
os.makedirs("batches", exist_ok=True)
for bi in range(0, min(len(insts), 300), 100):
    chunk=insts[bi:bi+100]
    open("batches/b%03d.txt"%bi, "w").write("\n".join("0x%X 0x3800"%v for v in chunk))
print("batches written:", len(os.listdir("batches")))
