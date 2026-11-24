import struct, glob, os
e=0x12D0F1C10
hexv="%X"%(e+0x33C)
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x8], key=os.path.getmtime)
raw=open(fs[-1],"rb").read()
v=struct.unpack_from("<I",raw,0)[0]
print("+0x33C = 0x%08X   bit1 = %d" % (v, (v>>1)&1))
open("f33c.txt","w").write("0x%X"%v)
