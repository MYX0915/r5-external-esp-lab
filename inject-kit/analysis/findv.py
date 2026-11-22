import numpy as np, glob, os, collections
g=collections.defaultdict(list)
for pid in range(4,13):
    for f in glob.glob(r"C:\ProgramData\scdump\%d_*.bin"%pid):
        if os.path.getsize(f)!=0x200: continue
        vt=int(np.fromfile(f,dtype=np.uint64,count=1)[0])
        va=os.path.basename(f).split("_")[1].split(".")[0]
        if vt: g[vt].append(va)
print("classes:", len(g))
tgt=0x7FF779A400E8
print("local vtable 0x%X -> instances: %s" % (tgt, g.get(tgt, "NOT FOUND")[:12]))
print("count:", len(g.get(tgt,[])))
