import numpy as np, glob, os, collections
fs=[f for f in glob.glob(r"C:\ProgramData\scdump\2_*.bin") if os.path.getsize(f)>=8]
groups=collections.defaultdict(list)
for f in fs:
    vt=int(np.fromfile(f,dtype=np.uint64,count=1)[0])
    groups[vt].append(os.path.basename(f).split("_")[1].split(".")[0])
print("objects:", len(fs), " classes:", len(groups))
for vt,lst in sorted(groups.items(), key=lambda kv:-len(kv[1]))[:6]:
    print("  vtable 0x%-14X count=%d" % (vt, len(lst)))
