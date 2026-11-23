import struct, glob, os
td=0x7FF689680000+0x403E588
hexv="%X"%td
fs=sorted([q for q in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(q)==0x40], key=os.path.getmtime)
raw=open(fs[-1],"rb").read()
print("TypeDescriptor @0x%X" % td)
print("  ? 16 ??:", raw[:16].hex())
# ????? +0x10
for off in (0x08,0x10):
    s=raw[off:]
    end=0
    while end<len(s) and 32<=s[end]<127: end+=1
    if end>3:
        print("   +0x%02X ??: %s" % (off, s[:end].decode('latin1')))
