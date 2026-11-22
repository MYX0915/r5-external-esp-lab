import numpy as np, glob, os, collections
fs=[f for f in glob.glob(r"C:\ProgramData\scdump\3?_*.bin") if os.path.getsize(f)==0x200]
print("dumped:", len(fs))
g=collections.defaultdict(list)
for f in fs:
    vt=int(np.fromfile(f,dtype=np.uint64,count=1)[0])
    if vt: g[vt].append(os.path.basename(f).split("_")[1].split(".")[0])
for vt,lst in sorted(g.items(), key=lambda kv:-len(kv[1]))[:10]:
    print("  vtable 0x%-14X count=%-3d %s" % (vt, len(lst), lst[:2]))
