import numpy as np, glob, os, struct
f=[p for p in glob.glob(r"C:\ProgramData\scdump\*_35D43570.bin") if os.path.getsize(p)==0x200]
if not f:
    print("no dump for own instance"); raise SystemExit
vt=int(np.fromfile(max(f,key=os.path.getmtime),dtype=np.uint64,count=1)[0])
print("my vtable = 0x%X" % vt)
same=[]
for p in glob.glob(r"C:\ProgramData\scdump\*_*.bin"):
    if os.path.getsize(p)!=0x200: continue
    v=int(np.fromfile(p,dtype=np.uint64,count=1)[0])
    if v==vt: same.append("0x"+os.path.basename(p).split("_")[1].split(".")[0])
print("same-class dumps:", len(same), same[:10])
open("remote.txt","w").write("\n".join("%s 0x2000"%a for a in same if a!="0x35D43570")[:2000])
