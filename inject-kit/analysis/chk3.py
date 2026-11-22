import struct, glob, os
fs=[f for f in glob.glob(r"C:\ProgramData\scdump\*_*.bin") if os.path.getsize(f)==0x3800]
fs.sort(key=os.path.getmtime, reverse=True)
print("newest 8 dumps:")
for f in fs[:8]:
    raw=open(f,"rb").read()
    vt=struct.unpack_from("<Q", raw, 0)[0]
    p=struct.unpack_from("<3f", raw, 0x376C)
    print("  %-20s vtable=0x%X  +0x376C=(%9.1f,%9.1f,%9.1f)" % (os.path.basename(f), vt, p[0],p[1],p[2]))
