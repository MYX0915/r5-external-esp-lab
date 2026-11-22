import struct, glob, os
t=""
try: t=open("vmptr.txt").read().split()[0]
except: pass
if not t:
    print("no view matrix pointer"); raise SystemExit
hexv=t[2:]
fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)>=0x10]
if fs:
    raw=open(max(fs,key=os.path.getmtime),"rb").read()
    m=struct.unpack_from("<16f", raw, 0)
    print("view matrix @%s:" % hexv)
    for r in range(4):
        print("   %8.4f %8.4f %8.4f %8.4f" % m[r*4:r*4+4])
