import numpy as np, glob, os, collections
groups=collections.defaultdict(list)
for f in glob.glob(r"C:\ProgramData\scdump\8_*.bin"):
    if os.path.getsize(f) < 8: continue
    vt=int(np.fromfile(f,dtype=np.uint64,count=1)[0])
    groups[vt].append(os.path.basename(f).split("_")[1].split(".")[0])
tgt=groups[0x7FF68AD9C678]
print("dummy class members:", tgt)
open("dummy_req.txt","w").write("\n".join("0x%s 0x8000"%a for a in tgt))
