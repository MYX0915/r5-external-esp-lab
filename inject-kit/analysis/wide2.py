import numpy as np
arr=np.fromfile(r"C:\ProgramData\scdump\12_7FF63C4D15D8.bin", dtype=np.uint8)
q=arr.view(np.uint64)[::4]
nz=np.nonzero(q)[0]
sel=[int(i) for i in nz if i>100][:60]
open("wide2_req.txt","w").write("\n".join("0x%X 0x4000"%int(q[i]) for i in sel))
print("prepared", len(sel))
