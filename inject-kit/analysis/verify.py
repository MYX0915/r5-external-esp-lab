import numpy as np, struct
arr=np.fromfile(r"C:\ProgramData\scdump\3_7FF68E8115D8.bin", dtype=np.uint8)
q=arr.view(np.uint64)[::4]
# our own player instance from the ESP feed
feed=open(r"C:\ProgramData\sc_feed.bin","rb").read()
myinst=struct.unpack_from("<Q",feed,56)[0]
print("local player instance = 0x%X" % myinst)
idx=np.nonzero(q==myinst)[0]
print("found in entity array at indices:", idx[:5].tolist())
nz=np.nonzero(q)[0]
print("total non-zero entries:", len(nz), "first idx:", nz[:5].tolist())
# how many entries are < 0x1000000000 (heap)
heap=[i for i in nz if q[i] < 0x1000000000]
print("heap-looking entries:", len(heap))
