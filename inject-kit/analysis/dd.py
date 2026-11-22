import struct, glob, os
for hexv in ("120127980","132729D90"):
    fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x2000]
    if not fs: print("%s: no dump" % hexv); continue
    raw=open(fs[0],"rb").read()
    vt=struct.unpack_from("<Q", raw, 0)[0]
    p170=struct.unpack_from("<Q", raw, 0x170)[0]
    p376=struct.unpack_from("<3f", raw, 0x376C)
    pfd0=struct.unpack_from("<Q", raw, 0xFD0)[0]
    print("0x%s vt=0x%X" % (hexv, vt))
    print("   +0x170 = 0x%X" % p170)
    print("   +0xFD0 = 0x%X" % pfd0)
    print("   +0x376C = (%.1f,%.1f,%.1f)" % p376)
    open("probe_dummy_%s.txt"%hexv,"w").write("p 0x%X\n" % p170)
