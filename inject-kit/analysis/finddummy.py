import numpy as np, glob, os, struct, math
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
cam=np.array(struct.unpack_from("<3f",f,8))
print("cam:", ["%.1f"%v for v in cam])
fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_7FF77D4D15D8.bin") if os.path.getsize(p)==0x200000]
a=np.fromfile(max(fs,key=os.path.getmtime), dtype=np.uint8)
q=a.view(np.uint64)[::4]
nz=np.nonzero(q)[0]
insts=[int(q[i]) for i in nz if i>100 and (int(q[i])>>47)==0 and int(q[i])>=0x10000]
k=max(1, math.ceil(len(insts)/60))
sel=insts[::k][:60]
open("scan60.txt","w").write("\n".join("0x%X"%v for v in sel))
print("instances=%d sampled=%d" % (len(insts), len(sel)))
