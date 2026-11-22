import numpy as np, glob, os
fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_7FF77D4D15D8.bin") if os.path.getsize(p)==0x200000]
f=max(fs, key=os.path.getmtime)
arr=np.fromfile(f,dtype=np.uint8); q=arr.view(np.uint64)[::4]
nz=np.nonzero(q)[0]
sel=[(int(i),int(q[i])) for i in nz if i>100][:16]
open("ents16.txt","w").write("\n".join("0x%X 0x2000"%v for _,v in sel))
print("prepared", len(sel))
