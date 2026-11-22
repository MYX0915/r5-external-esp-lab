import numpy as np, struct
p=np.fromfile(r"C:\ProgramData\scdump\7_1C10D7110.bin", dtype=np.uint8)
arr=np.fromfile(r"C:\ProgramData\scdump\5_7FF63C4D15D8.bin", dtype=np.uint8)
q=arr.view(np.uint64)[::4]
for slot in range(3):
    off=0x1958+0x58+slot*4
    h=struct.unpack_from("<I", p, off)[0]
    print("slot %d handle=0x%08X index=%d serial=%d" % (slot, h, h & 0xFFFF, h >> 16))
    if h not in (0, 0xFFFFFFFF):
        i=h & 0xFFFF
        inst,ser=struct.unpack_from("<QI", arr, i*0x20)
        print("      -> entry inst=0x%X serial=%d (want %d) match=%s" % (inst,ser,h>>16, ser==(h>>16)))
