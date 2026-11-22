import numpy as np, glob, os, collections
fs=[f for f in glob.glob(r"C:\ProgramData\scdump\12_*.bin") if os.path.getsize(f)>=8]
groups=collections.defaultdict(list)
for f in fs:
    vt=int(np.fromfile(f,dtype=np.uint64,count=1)[0])
    groups[vt].append(os.path.basename(f).split("_")[1].split(".")[0])
print("objects:", len(fs), "classes:", len(groups))
for vt,lst in sorted(groups.items(), key=lambda kv:-len(kv[1]))[:6]:
    print("  vtable 0x%-12X count=%-3d %s" % (vt,len(lst),lst[:3]))
import json
best=max(groups.items(), key=lambda kv: len(kv[1]) if 4<=len(kv[1])<=8 else 0)
open("dummy2.txt","w").write("\n".join("0x%s 0x20000"%a for a in best[1]))
print("dummy class chosen: vtable 0x%X members=%d" % (best[0], len(best[1])))
