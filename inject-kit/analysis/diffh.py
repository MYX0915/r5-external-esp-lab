import numpy as np, os, glob
D=r"C:\ProgramData\scdump"
for f1 in sorted(glob.glob(os.path.join(D,"1_h*.bin"))):
    name=os.path.basename(f1)[2:]
    f2=os.path.join(D,"2_"+name)
    if not os.path.exists(f2): print(name,"no pair"); continue
    a=np.fromfile(f1,dtype=np.uint8); b=np.fromfile(f2,dtype=np.uint8)
    n=min(len(a),len(b))
    d=(a[:n]!=b[:n]).sum()
    print("%-22s %6.1f MB changed=%9d (%.2f%%)" % (name, n/1048576, d, 100.0*d/n))
