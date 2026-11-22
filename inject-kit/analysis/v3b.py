import numpy as np
arr=np.fromfile(r"C:\ProgramData\scdump\1_7FF68E8115D8.bin", dtype=np.uint8)
q=arr.view(np.uint64)[::4]
nz=np.nonzero(q)[0]
insts=[int(q[i]) for i in nz if i>100 and (int(q[i])>>47)==0 and int(q[i])>=0x10000]
print("instances:", len(insts))
open("vt3.txt","w").write("\n".join("0x%X 0x300"%v for v in insts[:120]))
