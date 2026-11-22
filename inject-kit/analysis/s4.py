import numpy as np, glob
f=[p for p in glob.glob(r"C:\ProgramData\scdump\3_*.bin") if '7FF68E8115D8' in p]
print("file:", f)
if f:
    arr=np.fromfile(f[0],dtype=np.uint8)
    q=arr.view(np.uint64)[::4]
    nz=np.nonzero(q)[0]
    print("non-zero entries:", len(nz))
    sel=[int(q[i]) for i in nz if i>100][:8]
    print("sample:", [hex(v) for v in sel])
    open("t3.txt","w").write("\n".join("0x%X 0x8000"%v for v in sel))
