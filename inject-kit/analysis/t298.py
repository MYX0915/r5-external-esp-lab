import struct, glob, os
for a in (0xCD329B70,0xCDCDCEE0,0x132C64FD0):
    hexv="%X"%a
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x2C0], key=os.path.getmtime)
    if not fs: print("0x%X ? dump" % a); continue
    raw=open(fs[-1],"rb").read()
    p298=struct.unpack_from("<Q", raw, 0x298)[0]
    ok = 0x10000 < p298 < 0x7FFF00000000
    print("0x%X  +0x298 = 0x%016X  %s" % (a,p298,"? ????" if ok else "? ???"))
