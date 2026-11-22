import struct, glob, os
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
inst=struct.unpack_from("<Q",f,56)[0]
pos=struct.unpack_from("<3f",f,32)
print("local inst=0x%X pos=(%.1f,%.1f,%.1f)" % (inst,pos[0],pos[1],pos[2]))
fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_*.bin") if os.path.getsize(p)==0x8000]
# newest own-object dump
import time
cand=[p for p in fs if ("_%X.bin"%inst) in p]
print("own dump:", [os.path.basename(x) for x in cand])
if cand:
    raw=open(cand[0],"rb").read()
    p170=struct.unpack_from("<Q", raw, 0x170)[0]
    pfd0=struct.unpack_from("<Q", raw, 0xFD0)[0]
    print("entity+0x170 = 0x%X   (as Vector*)" % p170)
    print("entity+0xFD0 = 0x%X   (studioHdr)" % pfd0)
    open("ptr170.txt","w").write("0x%X 0x10\n" % p170 if 0x10000<p170<0x7FFF00000000 else "")
    open("ptrfd0.txt","w").write("0x%X 0x1000\n" % pfd0 if 0x10000<pfd0<0x7FFF00000000 else "")
