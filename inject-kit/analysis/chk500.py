import struct, glob, os
me=open("me500.txt").read().split()[0]; hexv=me[2:]
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x600], key=os.path.getmtime)
raw=open(fs[-1],"rb").read()
p=struct.unpack_from("<Q", raw, 0x500)[0]
print("?? +0x500 = 0x%X  (%s)" % (p, "????" if 0x10000<p<0x7FFF00000000 else "??"))
if 0x10000<p<0x7FFF00000000:
    open("nameptr.txt","w").write("0x%X 0x40"%p)
# ??? 0x480~0x540 ?????
print("\n???????:")
for off in range(0x480,0x560,8):
    v=struct.unpack_from("<Q", raw, off)[0]
    if 0x10000<v<0x7FFF00000000 and (v&7)==0:
        print("   +0x%03X = 0x%X" % (off,v))
