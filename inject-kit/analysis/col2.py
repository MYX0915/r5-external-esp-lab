import struct, glob, os
p=0x7FF68C7400E0
hexv="%X"%p
fs=sorted([q for q in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(q)==0x8], key=os.path.getmtime)
raw=open(fs[-1],"rb").read()
col=struct.unpack_from("<Q", raw, 0)[0]
print("vtable-8 = 0x%X" % col)
print("????: %s" % (0x10000<col<0x7FFF00000000))
open("colv.txt","w").write("0x%X 0x20\n"%col)
