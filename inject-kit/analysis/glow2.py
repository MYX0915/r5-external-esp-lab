import struct, glob, os
tests=[("GLOW_TYPE",0x2C4),("GLOW_COLOR",0x1D0),("GLOW_CONTEXT",0x3C8),("GLOW_VISIBLE_TYPE",0x3D0),
       ("m_iHealth",0x440),("m_iTeamNum",0x450),("m_lifeState",0x798)]
for name,a in (("me", open("me3.txt").read().split()[0]), ("dummy", open("targets.txt").read().split()[0])):
    hexv=a[2:]
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x800], key=os.path.getmtime)
    if not fs: print("%s no dump"%name); continue
    raw=open(fs[-1],"rb").read()
    print("=== %s %s ===" % (name,a))
    for nm,off in tests:
        v32=struct.unpack_from("<i", raw, off)[0]
        print("   %-18s +0x%03X = %d" % (nm,off,v32))
