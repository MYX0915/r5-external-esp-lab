import struct, glob, os
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_7FF68979A390.bin") if os.path.getsize(p)>=0x40], key=os.path.getmtime)
if not fs: print("no dump"); raise SystemExit
raw=open(fs[-1],"rb").read()
q=struct.unpack_from("<Q", raw, 0)[0]
print("first qword = 0x%X  (valid ptr: %s)" % (q, 0x10000<q<0x7FFF00000000))
m=struct.unpack_from("<16f", raw, 0)
print("as 4x4:")
for r in range(4):
    print("   %12.5f %12.5f %12.5f %12.5f" % m[r*4:r*4+4])
if 0x10000<q<0x7FFF00000000:
    open("vm.txt","w").write("0x%X 0x40"%q)
