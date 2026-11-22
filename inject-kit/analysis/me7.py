import struct, glob, os
inst=open("me5.txt").read().split()[0]; hexv=inst[2:]
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x4000], key=os.path.getmtime)
raw=open(fs[-1],"rb").read()
vt=struct.unpack_from("<Q", raw, 0)[0]
p376=struct.unpack_from("<3f", raw, 0x376C)
print("file:", os.path.basename(fs[-1]))
print("vtable = 0x%X" % vt)
print("+0x376C = (%.1f, %.1f, %.1f)" % p376)
open("vt2.txt","w").write("0x%X"%vt)
