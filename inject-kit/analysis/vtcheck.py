import struct, glob, os, collections
me=int(open("me.txt").read().strip(),16)
# ????
hexv="%X"%me
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x8], key=os.path.getmtime)
lvt=struct.unpack_from("<Q",open(fs[-1],"rb").read(),0)[0] if fs else 0
print("?????? = 0x%X" % lvt)
# ????
big=[p for p in glob.glob(r"C:\ProgramData\scdump\*_*.bin") if os.path.getsize(p)==0x200000]
big.sort(key=os.path.getmtime, reverse=True)
if not big: print("????? dump"); raise SystemExit
import numpy as np
a=np.fromfile(big[0], dtype=np.uint8)
q=a.view(np.uint64)[::4]
insts=[int(q[i]) for i in np.nonzero(q)[0] if (int(q[i])>>47)==0 and int(q[i])>=0x10000]
print("???? = %d" % len(insts))
print("? 10 ???: %s" % ["0x%X"%v for v in insts[:10]])
