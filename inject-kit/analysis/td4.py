import struct, glob, os
td=int(open("td3.txt").read().split()[0],16)
hexv="%X"%td
fs=sorted([q for q in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(q)==0x30], key=os.path.getmtime)
raw=open(fs[-1],"rb").read()
print("TD @0x%X ?16??: %s" % (td, raw[:16].hex()))
for off in (0x08,0x10):
    s=raw[off:]; e=0
    while e<len(s) and 32<=s[e]<127: e+=1
    if e>3: print("   +0x%02X = %s" % (off, s[:e].decode('latin1')))
