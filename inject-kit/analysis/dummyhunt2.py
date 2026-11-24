import struct, glob, os
d=0x11BB75EC0
hexv="%X"%d
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x8], key=os.path.getmtime)
vt=struct.unpack_from("<Q",open(fs[-1],"rb").read(),0)[0] if fs else 0
print("?? 0x%X  ??=0x%X" % (d,vt))
hexv2="%X"%(d+0x100)
fs2=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv2) if os.path.getsize(p)==0x600], key=os.path.getmtime)
if not fs2: print("?dump"); raise SystemExit
raw=open(fs2[-1],"rb").read()
print("\n????1..1000???:")
c=0
for off in range(0,0x600-4,4):
    v=struct.unpack_from("<i",raw,off)[0]
    if 1<=v<=1000:
        print("  +0x%03X = %d" % (0x100+off, v)); c+=1
        if c>=16: break
