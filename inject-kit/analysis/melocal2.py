import struct, glob, os
me=0xF702D940
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
pos=struct.unpack_from("<3f",f,32)
print("feed ??: (%.2f, %.2f, %.2f)" % pos)
hexv="%X"%(me+0x1000)
fs=sorted([x for x in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(x)==0x1000], key=os.path.getmtime)
if not fs: print("?dump"); raise SystemExit
raw=open(fs[-1],"rb").read()
print("\n???? +0x1200~0x12A0 ??????? = 0x1000 + ??????:")
for fo in range(0x200,0x2A0,4):
    t=struct.unpack_from("<3f",raw,fo)
    if all(abs(v)<40000 for v in t) and any(abs(v)>50 for v in t):
        print("  +0x%04X  (%.2f, %.2f, %.2f)" % (0x1000+fo,t[0],t[1],t[2]))
