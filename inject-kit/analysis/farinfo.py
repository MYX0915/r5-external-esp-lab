import struct, glob, os
e=0x12053D9A0
def rd(off):
    hexv="%X"%(e+off)
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x8], key=os.path.getmtime)
    if not fs: return None
    return open(fs[-1],"rb").read()
r=rd(0)
print("???? 0x%X  ?? = 0x%X" % (e, struct.unpack_from("<Q",r,0)[0] if r else 0))
for off,nm in ((0x340,"team"),(0x330,"+0x330"),(0x18C,"+0x18C")):
    r=rd(off)
    if r: print("  %-8s = %d" % (nm, struct.unpack_from("<i",r,0)[0]))
