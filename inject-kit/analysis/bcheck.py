import struct, glob, os
b=0x1293AE950
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
pos=struct.unpack_from("<3f",f,32)
print("??: (%.1f,%.1f,%.1f)\n" % pos)
hexv="%X"%(b+0x3000)
fs=sorted([x for x in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(x)==0x1000], key=os.path.getmtime)
if not fs: print("?dump"); raise SystemExit
raw=open(fs[-1],"rb").read()
print("??B +0x3700~0x3820 ??:")
for fo in range(0x700,0x820,4):
    t=struct.unpack_from("<3f",raw,fo)
    print("  +0x%04X  (%.2f, %.2f, %.2f)" % (0x3000+fo,t[0],t[1],t[2]))
