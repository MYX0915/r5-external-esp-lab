import struct, glob, os
e=0x1268A0920
def rd(va,size):
    hexv="%X"%va
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==size], key=os.path.getmtime)
    return open(fs[-1],"rb").read() if fs else None
raw=rd(e+0x2A0,0x20)
print("?? 0x%X ????:" % e)
if raw:
    print("  +0x2A0..0x2A3 contexts = %s" % " ".join("%02X"%b for b in raw[0:4]))
    print("  +0x2A4..0x2A7           = %s" % " ".join("%02X"%b for b in raw[4:8]))
    print("  +0x2A8..0x2AB focused  = %s" % " ".join("%02X"%b for b in raw[8:12]))
    print("  +0x2AC..0x2AF fadeDur  = %s" % " ".join("%02X"%b for b in raw[12:16]))
    print("  +0x2B0..0x2B3           = %s" % " ".join("%02X"%b for b in raw[16:20]))
    print("  +0x2B4..0x2B7 parity   = %s" % " ".join("%02X"%b for b in raw[20:24]))
    print("  +0x2B8..0x2BF           = %s" % " ".join("%02X"%b for b in raw[24:32]))
raw2=rd(e+0x1D4,0x8)
if raw2:
    print("\n  +0x1D4 teamIndex = %d" % struct.unpack_from("<i",raw2,0)[0])
    print("  +0x1E4 teamBits  = 0x%08X" % struct.unpack_from("<I",raw2,0x10 if len(raw2)>0x10 else 0)[0] if len(raw2)>0x10 else "")
