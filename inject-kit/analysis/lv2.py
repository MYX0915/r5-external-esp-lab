import numpy as np, glob, os
fs=[f for f in glob.glob(r"C:\ProgramData\scdump\*_13016BFB0.bin") if os.path.getsize(f)>=0x1000]
print("files:", [os.path.basename(x) for x in fs])
if fs:
    f=max(fs, key=os.path.getmtime)
    vt=int(np.fromfile(f,dtype=np.uint64,count=1)[0])
    print("local vtable = 0x%X" % vt)
    open("vtlocal.txt","w").write("vd 0x%X\n" % vt)
