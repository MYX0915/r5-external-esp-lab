import numpy as np, glob, os, struct
fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_7FF77D4D15D8.bin") if os.path.getsize(p)==0x200000]
f=max(fs, key=os.path.getmtime)
arr=np.fromfile(f,dtype=np.uint8); q=arr.view(np.uint64)[::4]
feed=open(r"C:\ProgramData\sc_feed.bin","rb").read()
me=struct.unpack_from("<Q",feed,56)[0]
print("array:", os.path.basename(f), " me=0x%X" % me)
nz=np.nonzero(q)[0]
insts=[(int(i),int(q[i])) for i in nz if 100<i<4000]
print("low-index entities:", len(insts))
open("low2.txt","w").write("\n".join("0x%X 0x200"%v for _,v in insts[:60]))
open("memap.txt","w").write("\n".join("%d 0x%X"%(i,v) for i,v in insts[:60]))
