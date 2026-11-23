import struct, glob, os
inst=open("me.txt").read().strip()
hexv=inst[2:]
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x200], key=os.path.getmtime)
raw=open(fs[-1],"rb").read()
vt=struct.unpack_from("<Q", raw, 0)[0]
print("our instance %s  vtable=0x%X" % (inst, vt))
open("vt.txt","w").write("0x%X"%vt)
# ?????
import io
lines=open(r"C:\ProgramData\sc_classes.txt").read().splitlines()
for l in lines:
    if l.startswith("0x"):
        parts=l.split()
        if int(parts[0],16)==vt:
            print("  ? ????:", l)
            break
else:
    print("  ? ?????? vtable???????????")
