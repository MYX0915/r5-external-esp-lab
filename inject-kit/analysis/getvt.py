import numpy as np, glob, os
fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_*.bin") if os.path.getsize(p)==0x200]
import time
f=max(fs,key=os.path.getmtime)
vt=int(np.fromfile(f,dtype=np.uint64,count=1)[0])
print("my vtable = 0x%X" % vt)
open("myvt.txt","w").write("0x%X"%vt)
