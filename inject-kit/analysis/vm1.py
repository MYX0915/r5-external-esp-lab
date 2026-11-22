import struct, glob, os
fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_7FF777A9390.bin") if os.path.getsize(p)>=0x10]
print("files:", [(os.path.basename(x),os.path.getsize(x)) for x in fs])
if fs:
    raw=open(max(fs,key=os.path.getmtime),"rb").read()
    ptr=struct.unpack_from("<Q", raw, 0)[0]
    print("view matrix pointer = 0x%X" % ptr)
    open("vmptr.txt","w").write("0x%X 0x40\n" % ptr if 0x10000<ptr<0x7FFF00000000 else "")
