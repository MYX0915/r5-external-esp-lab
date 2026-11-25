import struct, glob, os
me=0xF702D940
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
pos=struct.unpack_from("<3f",f,32)
print("feed ??: (%.2f, %.2f, %.2f)" % pos)
hexv="%X"%(me+0x1000)
fs=sorted([x for x in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(x)==0x1000], key=os.path.getmtime)
if not fs: print("?dump"); raise SystemExit
raw=open(fs[-1],"rb").read()
for off in (0x1240,0x1244,0x1248,0x124C,0x1250,0x1254,0x1258,0x125C,0x1260,0x1264,0x1268):
    t=struct.unpack_from("<3f",raw,off)
    print("  +0x%04X  (%.2f, %.2f, %.2f)" % (off,t[0],t[1],t[2]))
