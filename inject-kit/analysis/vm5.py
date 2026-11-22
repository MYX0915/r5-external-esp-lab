import struct, glob, os
fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_7FF776A9A390.bin") if os.path.getsize(p)>=0x40]
if not fs: print("no dump"); raise SystemExit
fs.sort(key=os.path.getmtime, reverse=True)
raw=open(fs[0],"rb").read()
print("file:", os.path.basename(fs[0]))
q0=struct.unpack_from("<Q", raw, 0)[0]
print("first qword (as ptr) = 0x%X  valid=%s" % (q0, 0x10000<q0<0x7FFF00000000 and (q0&7)==0))
m=struct.unpack_from("<16f", raw, 0)
print("as floats:")
for r in range(4):
    print("   %11.4f %11.4f %11.4f %11.4f" % m[r*4:r*4+4])
if 0x10000<q0<0x7FFF00000000 and (q0&7)==0:
    open("vmptr2.txt","w").write("0x%X 0x40\n" % q0)
