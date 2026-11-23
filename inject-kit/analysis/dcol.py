import struct, glob, os
vt=0x7FF68C769330
hexv="%X"%(vt-8)
fs=sorted([q for q in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(q)==0x8], key=os.path.getmtime)
col=struct.unpack_from("<Q", open(fs[-1],"rb").read(),0)[0]
print("dummy vtable-8 = 0x%X" % col)
open("col2v.txt","w").write("0x%X 0x20\n"%col)
