import struct, glob, os
me=int(open("me_now.txt").read().strip(),16)
hexv="%X"%(me+0x168)
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x10], key=os.path.getmtime)
raw=open(fs[-1],"rb").read()
print("  +0x168..0x177 = %s" % " ".join("%02X"%b for b in raw))
print("  ??+0x170 = (%.2f, %.2f, %.2f)" % struct.unpack_from("<3f", raw, 0x8))
