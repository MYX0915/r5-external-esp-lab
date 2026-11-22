import numpy as np, glob, os, collections
g=collections.defaultdict(list)
for line in open("census60.txt"):
    hexv=line.split()[0][2:]
    fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x200]
    if not fs: continue
    vt=int(np.fromfile(fs[0],dtype=np.uint64,count=1)[0])
    if vt: g[vt].append(hexv)
print("classes:", len(g))
for vt,l in sorted(g.items(), key=lambda kv:-len(kv[1]))[:8]:
    print("  0x%-14X count=%d  e.g. %s" % (vt, len(l), l[:3]))
