import numpy as np, struct
raw=open(r"C:\ProgramData\scdump\8_3B007B50.bin","rb").read()
for off in (0x1600, 0x1590, 0x1604, 0x15F8):
    v=struct.unpack_from("<i", raw, off)[0]
    print("  +0x%04X int32 = %d" % (off, v))
print("--- around 0x15F0 ---")
for off in range(0x15E0, 0x1620, 4):
    print("  +0x%04X = %d" % (off, struct.unpack_from("<i", raw, off)[0]))
