import struct
t=int(open("tbl.txt").read().split()[0],16)
hexv="%X"%t
import glob,os
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)>=0xD00], key=os.path.getmtime)
if not fs: print("no dump"); raise SystemExit
raw=open(fs[-1],"rb").read()
print("? @0x%X  ??? %d ???" % (t, 0xD00//0x34))
en=0; dis=0
for i in range(0xD00//0x34):
    off=i*0x34
    flags=struct.unpack_from("<I", raw, off)[0]
    p0=struct.unpack_from("<f", raw, off+4)[0]
    mode=struct.unpack_from("<i", raw, off+0x30)[0]
    on = bool(flags & 0x40000000)
    if on: en+=1
    else: dis+=1
    if i<12 or on:
        print("  [%3d] flags=0x%08X en=%d func=%d out=%d p0=%7.3f mode=%d" % (
            i, flags, 1 if on else 0, flags & 0xFF, (flags>>8)&0xFF, p0, mode))
print("\n?? %d ? / ??? %d ?" % (en,dis))
