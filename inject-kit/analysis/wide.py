import numpy as np
arr=np.fromfile(r"C:\ProgramData\scdump\12_7FF63C4D15D8.bin", dtype=np.uint8)
q=arr.view(np.uint64)[::4]
nz=np.nonzero(q)[0]
sel=[int(i) for i in nz if i>100][:60]
lines=[]
for i in sel:
    inst=int(q[i])
    lines.append("0x%X 0x2000" % inst)
open("wide_req.txt","w").write("\n".join(lines))
print("prepared", len(lines), "ranges; first idx", sel[0], "last", sel[-1])
