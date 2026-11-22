import glob, os, struct
for f in sorted(glob.glob(r"C:\ProgramData\scdump\7_*.bin")):
    raw=open(f,"rb").read()
    print(os.path.basename(f), "size=0x%X" % len(raw))
    if len(raw) > 0x180:
        for off in (0x170, 0x168, 0x178):
            v=struct.unpack_from("<Q", raw, off)[0]
            print("   +0x%03X = 0x%X" % (off, v))
    if len(raw) > 0x3780:
        pos=struct.unpack_from("<3f", raw, 0x376C)
        print("   +0x376C = (%.1f,%.1f,%.1f)" % pos)
