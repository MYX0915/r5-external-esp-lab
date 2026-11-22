import numpy as np, struct
h_raw=open(r"C:\ProgramData\scdump\5_7FF6396BDCD0.bin","rb").read()
arr=np.fromfile(r"C:\ProgramData\scdump\5_7FF63C4D15D8.bin", dtype=np.uint8)
h=struct.unpack_from("<I", h_raw, 0)[0]
print("handle = 0x%08X  index=%d  serial=%d" % (h, h & 0xFFFF, h >> 16))
if h == 0xFFFFFFFF:
    print("!! handle is FFFFFFFF (no local player)")
else:
    idx = h & 0xFFFF
    ser = h >> 16
    off = idx * 0x20
    inst, entry_ser = struct.unpack_from("<QI", arr, off)
    print("entry@0x%X  instance=0x%X  entry_serial=%d  (want %d)" % (off, inst, entry_ser, ser))
    print("serial match:", entry_ser == ser)
# how many non-zero entries?
q=arr.view(np.uint64)[::4]
nz=np.nonzero(q)[0]
print("non-zero entries:", len(nz), "first:", nz[:12].tolist())
