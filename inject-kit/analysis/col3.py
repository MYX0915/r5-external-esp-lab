import struct, glob, os
col=int(open("colv.txt").read().split()[0],16)
hexv="%X"%col
fs=sorted([q for q in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(q)==0x20], key=os.path.getmtime)
raw=open(fs[-1],"rb").read()
sig,off,cd,ptd,pchd,pself=struct.unpack_from("<IIIIII", raw, 0)
print("COL @0x%X" % col)
print("  signature          = 0x%X  (1 = x64)" % sig)
print("  offset             = 0x%X" % off)
print("  cdOffset           = 0x%X" % cd)
print("  pTypeDescriptor    = 0x%X" % ptd)
print("  pClassHierarchy    = 0x%X" % pchd)
print("  pSelf              = 0x%X" % pself)
if ptd:
    open("td2.txt","w").write("0x%X 0x40\n" % (0x7FF689680000+ptd))
