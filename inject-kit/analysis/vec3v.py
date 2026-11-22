import struct, glob, os
for line in open("vecptr2.txt"):
    va=line.split()[0]; hexv=va[2:]
    fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x10]
    if not fs:
        print("  %s -> (no dump)" % va); continue
    raw=open(fs[0],"rb").read()
    xyz=struct.unpack_from("<3f", raw, 0)
    print("  %s -> (%9.2f, %9.2f, %9.2f)" % (va, xyz[0], xyz[1], xyz[2]))
