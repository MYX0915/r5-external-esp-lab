import struct, glob, os
for a in ("ACB800","ACB870","B0DF90"):
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%a) if os.path.getsize(p)==0xC], key=os.path.getmtime)
    if not fs: print("  %s ?dump" % a); continue
    raw=open(fs[-1],"rb").read()
    print("  0x%s = (%.2f, %.2f, %.2f)" % (a, *struct.unpack_from("<3f",raw,0)))
