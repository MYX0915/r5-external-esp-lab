import numpy as np, glob, os, struct
hs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_7FF77[0-9A-F]*CD0.bin") if os.path.getsize(p)>=0x10]
arr=[p for p in glob.glob(r"C:\ProgramData\scdump\*_7FF77D4D15D8.bin") if os.path.getsize(p)==0x200000]
if not arr: print("no array"); raise SystemExit
a=np.fromfile(max(arr,key=os.path.getmtime), dtype=np.uint8)
q=a.view(np.uint64)[::4]
# handle slot
if hs:
    raw=open(max(hs,key=os.path.getmtime),"rb").read()
    h=struct.unpack_from("<I",raw,0)[0]
    print("handle=0x%08X index=%d serial=%d" % (h, h&0xFFFF, h>>16))
lines=[]
for i in range(1, 80):
    v=int(q[i])
    if v and v>=0x10000 and (v>>47)==0:
        lines.append("0x%X 0x200"%v)
open("low80.txt","w").write("\n".join(lines))
print("entities at index 1..79:", len(lines))
