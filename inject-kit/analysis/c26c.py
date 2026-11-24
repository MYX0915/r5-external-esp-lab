import glob, os
e=0x12D0F1C10
hexv="%X"%(e+0x26C)
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x8], key=os.path.getmtime)
raw=open(fs[-1],"rb").read()
print("  +0x26C = %d  %s" % (raw[0], "?? ?" if raw[0]==2 else "???"))
