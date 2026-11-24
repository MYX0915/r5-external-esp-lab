import glob, os
hexv="AC6FFB20"
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x1000], key=os.path.getmtime)
if fs:
    raw=open(fs[-1],"rb").read()
    print("  ??: %s" % os.path.basename(fs[-1]))
    print("  " + " ".join("%02X"%b for b in raw[:64]))
    nz=sum(1 for i in range(0,len(raw),4) if raw[i:i+4]!=b'\x00\x00\x00\x00')
    print("  ?? dword: %d / %d" % (nz, len(raw)//4))
