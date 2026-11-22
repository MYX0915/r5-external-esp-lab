import struct, glob, os
fs=sorted(glob.glob(r"C:\ProgramData\scdump\n*_*.bin"))
print("npc dumps:", len(fs))
for f in fs:
    if os.path.getsize(f) < 0x3780: continue
    raw=open(f,"rb").read()
    vt=struct.unpack_from("<Q", raw, 0)[0]
    p=struct.unpack_from("<3f", raw, 0x376C)
    ok = abs(p[0])>1 or abs(p[1])>1
    print("  %-26s vtable=0x%-14X +0x376C=(%9.1f,%9.1f,%9.1f) %s" % (os.path.basename(f), vt, p[0],p[1],p[2], "<== POS" if ok else ""))
