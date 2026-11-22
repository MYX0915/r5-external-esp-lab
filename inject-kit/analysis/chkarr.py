import numpy as np, glob, os
fs=[f for f in glob.glob(r"C:\ProgramData\scdump\*_7FF77D4D15D8.bin") if os.path.getsize(f)==0x200000]
print("array dumps:", [os.path.basename(x) for x in fs])
f=max(fs, key=os.path.getmtime)
arr=np.fromfile(f, dtype=np.uint8)
q=arr.view(np.uint64)[::4]
nz=np.nonzero(q)[0]
print("file:", os.path.basename(f), "non-zero:", len(nz))
tgt=0x13016BFB0
hit=np.nonzero(q==tgt)[0]
print("local inst 0x%X in array at:" % tgt, hit.tolist())
# also check the vtable value presence
tgt2=0x7FF779A400E8
print("vtable in array?", (q==tgt2).sum())
