import numpy as np, struct
arr=np.fromfile(r"C:\ProgramData\scdump\11_7FF68E8115D8.bin", dtype=np.uint8)
q=arr.view(np.uint64)[::4]
inst=0x12AD98230
idx=np.nonzero(q==inst)[0]
print("index in entity array:", idx.tolist())
raw=open(r"C:\ProgramData\scdump\21_12AD98230.bin","rb").read()
vt=struct.unpack_from("<Q", raw, 0)[0]
pos=struct.unpack_from("<3f", raw, 0x376C)
print("vtable = 0x%X" % vt)
print("+0x376C = (%.1f, %.1f, %.1f)" % pos)
