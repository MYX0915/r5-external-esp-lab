import numpy as np, glob, os
fs=[f for f in glob.glob(r"C:\ProgramData\scdump\*_7FF77*.bin") if os.path.getsize(f)==0x200000]
print("array file:", [os.path.basename(x) for x in fs])
arr=np.fromfile(fs[0], dtype=np.uint8)
q=arr.view(np.uint64)[::4]
nz=np.nonzero(q)[0]
insts=[int(q[i]) for i in nz if i>100 and (int(q[i])>>47)==0 and int(q[i])>=0x10000]
print("instances:", len(insts))
os.makedirs("vb", exist_ok=True)
for f in os.listdir("vb"): os.remove(os.path.join("vb",f))
for k in range(0, len(insts), 100):
    open("vb/v%03d.txt"%k,"w").write("\n".join("0x%X 0x200"%v for v in insts[k:k+100]))
print("batches:", len(os.listdir("vb")))
