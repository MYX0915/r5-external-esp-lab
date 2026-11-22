import struct, glob, os, time
for _ in range(40):
    f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
    if len(f)>=64 and struct.unpack_from("<I",f,48)[0]:
        inst=struct.unpack_from("<Q",f,56)[0]
        if inst: break
    time.sleep(0.1)
fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_%X.bin"%inst) if os.path.getsize(p)>=0x1000]
print("inst=0x%X  dumps:%s" % (inst,[os.path.basename(x) for x in fs]))
if fs:
    raw=open(max(fs,key=os.path.getmtime),"rb").read()
    for off in (0x40,0x38,0x48):
        v=struct.unpack_from("<Q", raw, off)[0]
        print("  +0x%02X = 0x%X %s" % (off, v, "PTR" if 0x10000<v<0x7FFF00000000 else ""))
    p=struct.unpack_from("<Q", raw, 0x40)[0]
    if 0x10000<p<0x7FFF00000000:
        open("tbl.txt","w").write("0x%X 0x400\n" % p)
