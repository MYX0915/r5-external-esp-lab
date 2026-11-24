import struct, glob, os
e=0x12519E500
hexv="%X"%(e+0x2A0)
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x18], key=os.path.getmtime)
raw=open(fs[-1],"rb").read()
print("?? 0x%X:" % e)
print("  contexts = %s" % " ".join("%02X"%b for b in raw[0:4]))
print("  focused  = %02X %02X %02X %02X" % (raw[8],raw[9],raw[10],raw[11]))
print("  fadeDur  = %02X %02X %02X %02X" % (raw[12],raw[13],raw[14],raw[15]))
print("  parity   = %02X %02X %02X %02X" % (raw[20],raw[21],raw[22],raw[23]))
open("orig_hl.txt","w").write("%d %d\n" % (raw[8], int.from_bytes(raw[20:24],'little')))
