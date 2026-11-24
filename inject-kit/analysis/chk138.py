import struct, glob, os
e=0x299FB1C0
hexv="%X"%(e+0x130)
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x30], key=os.path.getmtime)
raw=open(fs[-1],"rb").read()
h=struct.unpack_from("<I", raw, 0x8)[0]
print("entity 0x%X" % e)
print("  +0x138 = 0x%X   ?16(??)=0x%X  ?16(??)=0x%X" % (h, h & 0xFFFF, h >> 16))
print("  ??: +0x130=%08X +0x138=%08X +0x140=%08X" % (
      struct.unpack_from("<I",raw,0)[0], h, struct.unpack_from("<I",raw,0x10)[0]))
