import struct, glob, os
me=open("me3.txt").read().split()[0]
dummy=open("targets.txt").read().split()[0]
for name,a in (("me",me),("dummy",dummy)):
    hexv=a[2:]
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x800], key=os.path.getmtime)
    if not fs: print(name,"no dump"); continue
    raw=open(fs[-1],"rb").read()
    p=struct.unpack_from("<Q", raw, 0x298)[0]
    print("%-6s %s  +0x298 = 0x%X  (%s)" % (name,a,p,"????" if 0x10000<p<0x7FFF00000000 else "??"))
    if 0x10000<p<0x7FFF00000000:
        open("ctx_%s.txt"%name,"w").write("0x%X 0x10\n"%p)
