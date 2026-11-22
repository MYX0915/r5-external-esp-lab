import numpy as np, glob
f=sorted(glob.glob(r"C:\ProgramData\scdump\19_*.bin"))
print("array dump:", f)
if f:
    arr=np.fromfile(f[0],dtype=np.uint8)
    q=arr.view(np.uint64)[::4]
    nz=np.nonzero(q)[0]
    print("non-zero:", len(nz))
    sel=[int(q[i]) for i in nz if i>100][:40]
    open("npc40b.txt","w").write("\n".join("0x%X 0x8000"%v for v in sel))
    print("prepared", len(sel))
