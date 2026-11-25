import struct, glob, os
me=0xF702D940
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
pos=struct.unpack_from("<3f",f,32)
print("feed ??: (%.2f, %.2f, %.2f)\n" % pos)
hexv="%X"%me
fs=sorted([x for x in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(x)==0x1000], key=os.path.getmtime)
if not fs: print("?dump"); raise SystemExit
raw=open(fs[-1],"rb").read()
print("???? 0x000~0xFFF ??????????:")
for off in range(0,0x1000-12,4):
    t=struct.unpack_from("<3f",raw,off)
    if not all(abs(v)<40000 for v in t): continue
    if not any(abs(v)>300 for v in t): continue
    print("  +0x%04X  (%.2f, %.2f, %.2f)" % (off,t[0],t[1],t[2]))
