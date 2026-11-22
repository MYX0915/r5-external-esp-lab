import numpy as np, glob, os
fs=[f for f in glob.glob(r"C:\ProgramData\scdump\*_7FF77D4D15D8.bin") if os.path.getsize(f)==0x200000]
f=max(fs, key=os.path.getmtime)
arr=np.fromfile(f, dtype=np.uint8); q=arr.view(np.uint64)[::4]
nz=np.nonzero(q)[0]
print("file:", os.path.basename(f), "non-zero:", len(nz))
tgt=0x13016BFB0
print("local inst in array:", np.nonzero(q==tgt)[0].tolist())
insts=[int(q[i]) for i in nz if i>100 and (int(q[i])>>47)==0 and int(q[i])>=0x10000]
print("instances:", len(insts))
open("allinst.txt","w").write("\n".join("0x%X 0x200"%v for v in insts))
