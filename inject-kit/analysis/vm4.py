import struct, glob, os
fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_7FF776A9A390.bin") if os.path.getsize(p)>=0x40]
if not fs: print("no dump"); raise SystemExit
raw=open(max(fs,key=os.path.getmtime),"rb").read()
m=struct.unpack_from("<16f", raw, 0)
print("as 4x4:")
for r in range(4):
    print("   %11.4f %11.4f %11.4f %11.4f" % m[r*4:r*4+4])
print()
raw2=struct.unpack_from("<16f", raw, 0)
print("as 3x4 (4th col = translation):")
for r in range(4):
    print("   %11.4f %11.4f %11.4f | %11.4f" % (m[r*4],m[r*4+1],m[r*4+2],m[r*4+3]))
