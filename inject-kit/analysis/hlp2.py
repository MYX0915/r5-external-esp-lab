import struct, glob, os, numpy as np
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_131D12F00.bin") if os.path.getsize(p)==0x1000], key=os.path.getmtime)
if not fs: print("no dump"); raise SystemExit
raw=open(fs[-1],"rb").read()
print("=== 0x131D12F00 ? 32 ? qword ===")
for i in range(0,0x100,8):
    v=struct.unpack_from("<Q", raw, i)[0]
    tag="PTR" if 0x10000<v<0x7FFF00000000 and (v&7)==0 else ""
    print("   +0x%03X = 0x%-14X %s" % (i,v,tag))
