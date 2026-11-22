import numpy as np
arr=np.fromfile(r"C:\ProgramData\scdump\12_7FF63C4D15D8.bin", dtype=np.uint8)
q=arr.view(np.uint64)[::4]
nz=np.nonzero(q)[0]
print("non-zero entries:", len(nz))
sel=[(int(i), int(q[i])) for i in nz if i>100][:12]
for i,v in sel: print("  idx=%-6d inst=0x%X" % (i,v))
open("npc_req.txt","w").write("\n".join("0x%X 0x8000"%v for i,v in sel))
print("prepared", len(sel))
