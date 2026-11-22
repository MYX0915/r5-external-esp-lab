import struct, glob, os
f=sorted(glob.glob(r"C:\ProgramData\scdump\*_12AD98230.bin"), key=os.path.getmtime)
print("dumps:", [os.path.basename(x) for x in f])
for x in f:
    raw=open(x,"rb").read()
    if len(raw)<0x3780: continue
    p=struct.unpack_from("<3f", raw, 0x376C)
    print("  %-22s +0x376C = (%9.1f,%9.1f,%9.1f)" % (os.path.basename(x), p[0],p[1],p[2]))
