import struct, glob, os
b=0x1293AE950
hexv="%X"%b
fs=sorted([x for x in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(x)==0x1000], key=os.path.getmtime)
raw=open(fs[-1],"rb").read()
print("??B ???????:")
for off,name in ((0x18,"m_localOrigin?"),(0x20,"m_localOrigin?"),(0x28,"m_vecOrigin"),(0x2c,"m_origin"),
                 (0x170,"m_vecAbsOrigin"),(0x178,"m_localOrigin"),(0x940,"m_localOrigin"),(0x978,"?????")):
    t=struct.unpack_from("<3f",raw,off)
    n=struct.unpack_from("<3i",raw,off)
    print("  +0x%04X %-16s float(%.2f,%.2f,%.2f)  int(%d,%d,%d)" % (off,name,t[0],t[1],t[2],n[0],n[1],n[2]))
print("\n+0x40 / +0x50 ????? cell?:")
for off in (0x30,0x34,0x38,0x3c,0x40,0x44,0x48,0x50,0x58):
    f3=struct.unpack_from("<3f",raw,off)
    i3=struct.unpack_from("<3i",raw,off)
    print("  +0x%04X float(%.1f,%.1f,%.1f) int(%d,%d,%d)" % (off,f3[0],f3[1],f3[2],i3[0],i3[1],i3[2]))
