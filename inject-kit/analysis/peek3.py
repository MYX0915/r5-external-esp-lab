import numpy as np, os
D=r"C:\ProgramData\scdump"
a=np.fromfile(os.path.join(D,"1_mod1.bin"),dtype=np.float32)
b=np.fromfile(os.path.join(D,"2_mod1.bin"),dtype=np.float32)
base=0x003DA380//4
print("with3x4 window @0x3DA380:")
for i in range(0,56,8):
    print(" p1: " + " ".join(f"{v:10.3f}" if np.isfinite(v) else "       inf" for v in a[base+i:base+i+8]))
    print(" p2: " + " ".join(f"{v:10.3f}" if np.isfinite(v) else "       inf" for v in b[base+i:base+i+8]))
    print()
