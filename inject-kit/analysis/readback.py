import struct, glob, os
e=0xCD329B70
print("?? 0x%X ?????:" % e)
for off,name in ((0x1D0,'??RGB'),(0x2C4,'GlowMode'),(0x3C8,'context'),(0x3D0,'visibleType'),(0x480,'enable')):
    hexv="%X"%(e+off)
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x10], key=os.path.getmtime)
    if not fs: print("   %-12s ????" % name); continue
    raw=open(fs[-1],"rb").read()
    print("   %-12s +0x%03X = %s" % (name,off,raw[:8].hex(' ')))
