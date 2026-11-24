import glob, os
e=0x12B6FBF60
hexv="%X"%(e+0x294)
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x8], key=os.path.getmtime)
print("  ???? +0x294 = %d" % open(fs[-1],"rb").read()[0] if fs else "?dump")
