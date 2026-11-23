import struct, glob, os
me=open("me.txt").read().strip(); hexv=me[2:]
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x200], key=os.path.getmtime)
vt=struct.unpack_from("<Q", open(fs[-1],"rb").read(), 0)[0]
print("my vtable = 0x%X" % vt)
open("vt.txt","w").write("0x%X"%vt)
lines=[l for l in open(r"C:\ProgramData\sc_classes.txt") if l.startswith("0x")]
for l in lines:
    p=l.split()
    if int(p[0],16)==vt: print("???:", l.strip()); break
