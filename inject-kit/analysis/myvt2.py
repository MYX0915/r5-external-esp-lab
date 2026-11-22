import struct, glob, os
inst=open("me4.txt").read().split()[0]
hexv=inst[2:]
fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x4000]
raw=open(max(fs,key=os.path.getmtime),"rb").read()
vt=struct.unpack_from("<Q", raw, 0)[0]
p376=struct.unpack_from("<3f", raw, 0x376C)
p978=struct.unpack_from("<3f", raw, 0x978)
print("inst=%s  vtable=0x%X" % (inst, vt))
print("  +0x376C=(%.1f,%.1f,%.1f)" % p376)
print("  +0x978 =(%.1f,%.1f,%.1f)" % p978)
open("myvt.txt","w").write("0x%X"%vt)
