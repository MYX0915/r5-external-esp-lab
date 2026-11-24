import struct, glob, os
for obj,label in ((0x4924DA0,"?? k=84"),(0x4924DA0-0x60,"?? k=83")):
    hexv="%X"%obj
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x60], key=os.path.getmtime)
    if not fs: print("%s ?dump" % label); continue
    raw=open(fs[-1],"rb").read()
    print("=== %s @ 0x%X ===" % (label,obj))
    for i in range(0,0x60,0x10):
        f3=struct.unpack_from("<3f",raw,i)
        q=struct.unpack_from("<Q",raw,i)[0]
        tag=""
        if 0x7FF000000000<=q<=0x7FFFFFFFFFFF: tag=" ? vtable?"
        print("  +0x%02X  0x%016X  (%12.3f,%12.3f,%12.3f)%s" % (i,q,f3[0],f3[1],f3[2],tag))
    print()
