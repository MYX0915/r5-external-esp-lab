import struct, glob, os
fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_*.bin") if os.path.getsize(p)==0x2000]
f=max(fs, key=os.path.getmtime)
raw=open(f,"rb").read()
p170=struct.unpack_from("<Q", raw, 0x170)[0]
pfd0=struct.unpack_from("<Q", raw, 0xFD0)[0]
print("file:", os.path.basename(f))
print("+0x170 = 0x%X" % p170)
print("+0xFD0 = 0x%X" % pfd0)
open("probe.txt","w").write("p 0x%X\n" % p170)
