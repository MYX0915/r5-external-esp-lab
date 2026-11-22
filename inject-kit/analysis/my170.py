import struct, glob, os
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
inst=struct.unpack_from("<Q",f,56)[0]
me=struct.unpack_from("<3f",f,32)
print("my inst=0x%X pos=(%.1f,%.1f,%.1f)" % (inst,me[0],me[1],me[2]))
fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_%X.bin"%inst) if os.path.getsize(p)>=0x2000]
print("own dumps:", [os.path.basename(x) for x in fs])
if fs:
    raw=open(max(fs,key=os.path.getmtime),"rb").read()
    p170=struct.unpack_from("<Q", raw, 0x170)[0]
    pfd0=struct.unpack_from("<Q", raw, 0xFD0)[0]
    print("+0x170 = 0x%X" % p170)
    print("+0xFD0 = 0x%X" % pfd0)
    open("mine170.txt","w").write("0x%X 0x40\n" % p170)
