import numpy as np, glob, os, struct, collections
feed=open(r"C:\ProgramData\sc_feed.bin","rb").read()
me=struct.unpack_from("<Q",feed,56)[0]
fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_*.bin") if os.path.getsize(p)==0x200]
maps={}
for line in open("memap.txt"):
    i,v=line.split(); maps[v]=int(i)
byme=None; groups=collections.defaultdict(list)
for f in fs:
    va="0x"+os.path.basename(f).split("_")[1].split(".")[0]
    vt=int(np.fromfile(f,dtype=np.uint64,count=1)[0])
    if not vt: continue
    if int(va,16)==me: byme=vt
    groups[vt].append(va)
print("my vtable:", hex(byme) if byme else None, " classes:", len(groups))
if byme:
    same=groups.get(byme,[])
    print("same-class instances:", len(same), same[:8])
    open("remote.txt","w").write("\n".join("0x%s 0x2000"%a[2:] for a in same[:6] if int(a,16)!=me))
