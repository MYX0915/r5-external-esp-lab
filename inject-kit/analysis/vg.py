import numpy as np, glob, os, collections
g=collections.defaultdict(list)
tot=0
for pid in range(4,13):
    for f in glob.glob(r"C:\ProgramData\scdump\%d_*.bin"%pid):
        if os.path.getsize(f)!=0x200: continue
        tot+=1
        vt=int(np.fromfile(f,dtype=np.uint64,count=1)[0])
        va=os.path.basename(f).split("_")[1].split(".")[0]
        if vt: g[vt].append(va)
print("sampled:", tot, "classes:", len(g))
for vt,lst in sorted(g.items(), key=lambda kv:-len(kv[1]))[:12]:
    print("  vtable 0x%-14X count=%-3d %s" % (vt, len(lst), lst[:2]))
