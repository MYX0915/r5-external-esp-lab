import struct, glob, os
t=open("mine170.txt").read().split()[0]
hexv=t[2:]
fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)>=0x10]
print("dump:", [(os.path.basename(x), os.path.getsize(x)) for x in fs])
if fs:
    raw=open(max(fs,key=os.path.getmtime),"rb").read()
    v=struct.unpack_from("<3f", raw, 0)
    print("   [%s] = (%.2f, %.2f, %.2f)" % (hexv, v[0],v[1],v[2]))
    print("   raw:", raw[:24].hex(" "))
