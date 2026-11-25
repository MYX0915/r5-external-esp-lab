import struct, glob, os, numpy as np
# ?????? 64 ???????? +0x978 ?????
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
pos=np.array(struct.unpack_from("<3f",f,32), dtype=np.float64)
print("\n??: (%.1f,%.1f,%.1f)" % (pos[0],pos[1],pos[2]))
