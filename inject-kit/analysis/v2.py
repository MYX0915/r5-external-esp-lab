import numpy as np
arr=np.fromfile(r"C:\ProgramData\scdump\11_7FF68E8115D8.bin", dtype=np.uint8)
q=arr.view(np.uint64)[::4]
nz=np.nonzero(q)[0]
sel=[int(q[i]) for i in nz if i>100][:80]
open("vt2.txt","w").write("\n".join("0x%X 0x300"%v for v in sel))
print("prepared", len(sel))
