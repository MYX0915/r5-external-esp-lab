import struct, glob, os
def read(va,size):
    hexv="%X"%va
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==size], key=os.path.getmtime)
    return open(fs[-1],"rb").read() if fs else None
tbl=int(open("tblptr.txt").read().strip(),16)
for row in (50,2):
    va=tbl+row*0x34
    raw=read(va,0x34)
    print("\n=== row %d @ 0x%X ===" % (row,va))
    if not raw: print("  ????"); continue
    fb=struct.unpack_from("<I", raw, 0)[0]
    r,g,b=struct.unpack_from("<3f", raw, 4)
    p10,p14,p18,p1C=struct.unpack_from("<4f", raw, 0x10)
    maxd=struct.unpack_from("<f", raw, 0x20)[0]
    f24,f28,f2C,f30=struct.unpack_from("<4i", raw, 0x24)
    print("  functionBits=0x%08X  (b0=%d b1=%d b2=%d b3=%d)" % (fb, fb&0xFF,(fb>>8)&0xFF,(fb>>16)&0xFF,(fb>>24)&0xFF))
    print("  RGB=(%.3f, %.3f, %.3f)" % (r,g,b))
    print("  p10..p1C=(%.3f,%.3f,%.3f,%.3f)" % (p10,p14,p18,p1C))
    print("  maxDistance=%.1f" % maxd)
    print("  f24=%d f28=%d f2C=%d f30=%d" % (f24,f28,f2C,f30))
