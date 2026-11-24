import glob, os
e=0x12519E500
hexv="%X"%(e+0x2A0)
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x18], key=os.path.getmtime)
raw=open(fs[-1],"rb").read()
print("  contexts = %s" % " ".join("%02X"%b for b in raw[0:4]))
print("  focused  = %s" % " ".join("%02X"%b for b in raw[8:12]))
print("  parity   = %s" % " ".join("%02X"%b for b in raw[20:24]))
