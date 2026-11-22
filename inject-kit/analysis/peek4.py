import numpy as np, os
D=r"C:\ProgramData\scdump"
raw=np.fromfile(os.path.join(D,"3_2A374000.bin"),dtype=np.uint8)
f=raw.view(np.float32)
base=0xDA00//4
print("floats @0x2A374000+0xDA00 (4 per row):")
for i in range(0, 0x300//4, 4):
    vals=f[base+i:base+i+4]
    print("  0x%05X: " % (0xDA00 + i*4) + " ".join(f"{v:12.2f}" if np.isfinite(v) else "         inf" for v in vals))
