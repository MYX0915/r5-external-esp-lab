import struct, glob, os
col=0x7FF68C7400E8-8
hexv="%X"%col
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x20], key=os.path.getmtime)
if not fs: print("COL ????"); raise SystemExit
raw=open(fs[-1],"rb").read()
print("COL ??:")
for i in range(0,0x20,4):
    v=struct.unpack_from("<I", raw, i)[0]
    print("   +0x%02X = 0x%08X (%d)" % (i,v,v))
sig,off,cd,ptd,pchd,pself=struct.unpack_from("<IIIIII", raw, 0)
print("\nsignature=0x%X (?? 1)" % sig)
print("pTypeDescriptor RVA = 0x%X" % ptd)
print("pClassHierarchy RVA = 0x%X" % pchd)
open("td.txt","w").write("0x%X 0x40\n" % (0x7FF689680000+ptd))
