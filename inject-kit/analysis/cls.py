import numpy as np, glob, os, collections
g=collections.defaultdict(list)
for pid in range(4,13):
    for f in glob.glob(r"C:\ProgramData\scdump\%d_*.bin"%pid):
        if os.path.getsize(f)!=0x200: continue
        vt=int(np.fromfile(f,dtype=np.uint64,count=1)[0])
        va=os.path.basename(f).split("_")[1].split(".")[0]
        if vt: g[vt].append(va)
for vt in (0x7FF779AED5F8, 0x7FF779A60EF8, 0x7FF779A5C678):
    lst=g.get(vt,[])
    print("class 0x%X count=%d" % (vt, len(lst)))
    open("cls_%X.txt"%vt,"w").write("\n".join("0x%s 0x4000"%a for a in lst[:40]))
