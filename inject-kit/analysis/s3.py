import numpy as np, glob
f=[x for x in glob.glob(r"C:\ProgramData\scdump\*_7FF63C4D15D8.bin")]
f.sort(key=lambda p: __import__("os").path.getmtime(p), reverse=True)
arr=np.fromfile(f[0],dtype=np.uint8)
q=arr.view(np.uint64)[::4]
nz=np.nonzero(q)[0]
print("array:", f[0], "non-zero:", len(nz))
sel=[int(q[i]) for i in nz if i>100][:8]
open("t2.txt","w").write("\n".join("0x%X 0x8000"%v for v in sel))
print("sample:", [hex(v) for v in sel])
