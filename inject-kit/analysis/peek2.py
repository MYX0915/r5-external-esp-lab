import numpy as np, os
D=r"C:\ProgramData\scdump"
a=np.fromfile(os.path.join(D,"1_mod1.bin"),dtype=np.float32)
b=np.fromfile(os.path.join(D,"2_mod1.bin"),dtype=np.float32)
off=0x00B80000//4
print("page 0xB80000, first 48 floats:")
for i in range(0,48,8):
    print(" p1: " + " ".join(f"{v:11.4f}" if np.isfinite(v) else "        inf" for v in a[off+i:off+i+8]))
    print(" p2: " + " ".join(f"{v:11.4f}" if np.isfinite(v) else "        inf" for v in b[off+i:off+i+8]))
    print()
