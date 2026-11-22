import numpy as np
arr=np.fromfile(r"C:\ProgramData\scdump\4_7FF77D4D15D8.bin", dtype=np.uint8)
q=arr.view(np.uint64)[::4]
lines=[]
for i in range(1,41):
    v=int(q[i])
    if v and v>=0x10000 and (v>>47)==0:
        lines.append("0x%X 0x8000"%v)
open("low.txt","w").write("\n".join(lines))
print("prepared", len(lines))
