import struct, glob, os
for name,fn in (("+0x25C8 (m_viewangle)","ang25.txt"),("+0x1F84 (??????)","ang1f84.txt")):
    t=open(fn).read().split()[0]; hexv=t[2:]
    fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)>=0xC]
    if fs:
        raw=open(max(fs,key=os.path.getmtime),"rb").read()
        v=struct.unpack_from("<3f", raw, 0)
        print("%-24s = (%8.2f, %8.2f, %8.2f)" % (name, v[0], v[1], v[2]))
    else:
        print("%-24s = (no dump)" % name)
