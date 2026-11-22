import numpy as np, glob, os
fs=[f for f in glob.glob(r"C:\ProgramData\scdump\1?_*.bin") if os.path.getsize(f)==0x10]
f=max(fs, key=os.path.getmtime)
vt=int(np.fromfile(f,dtype=np.uint64,count=1)[0])
print("local player vtable = 0x%X" % vt)
open("vtlocal.txt","w").write("vd 0x%X\n" % vt)
