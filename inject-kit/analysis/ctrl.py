import glob, os
e=0x12B6FBF60
hexv="%X"%(e+0x2B0)
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x8], key=os.path.getmtime)
if not fs: print("? dump")
else:
    raw=open(fs[-1],"rb").read()
    print("  +0x2B0..0x2B7 = %s" % " ".join("%02X"%b for b in raw))
    print("  +0x2B5 = 0x%02X  %s" % (raw[5], "???? ?" if raw[5]==0xAA else "????? ?"))
