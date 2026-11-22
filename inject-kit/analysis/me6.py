import struct, glob, os
inst=open("me5.txt").read().split()[0]; hexv=inst[2:]
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x4000], key=os.path.getmtime)
raw=open(fs[-1],"rb").read()
vt=struct.unpack_from("<Q", raw, 0)[0]
p376=struct.unpack_from("<3f", raw, 0x376C)
p170=struct.unpack_from("<Q", raw, 0x170)
print("file=%s" % os.path.basename(fs[-1]))
print("vtable=0x%X  +0x376C=(%.1f,%.1f,%.1f)  +0x170=0x%X" % (vt,p376[0],p376[1],p376[2],p170))
open("vt2.txt","w").write("0x%X"%vt)
