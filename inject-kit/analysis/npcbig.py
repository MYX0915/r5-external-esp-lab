import numpy as np
arr=np.fromfile(r"C:\ProgramData\scdump\12_7FF63C4D15D8.bin", dtype=np.uint8)
q=arr.view(np.uint64)[::4]
nz=np.nonzero(q)[0]
sel=[(int(i),int(q[i])) for i in nz if i>100][:6]
lines=[]
for i,v in sel:
    lines.append("0x%X 0x20000" % v)   # 128KB per object
open("npc_big.txt","w").write("\n".join(lines))
print("\n".join("idx %d -> 0x%X"%(i,v) for i,v in sel))
