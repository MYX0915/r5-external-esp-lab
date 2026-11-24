import glob, os
e=int(open(r"C:\ProgramData\sc_addr.txt").readline().strip(),16)
hexv="%X"%(e+0x2A0)
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x18], key=os.path.getmtime)
raw=open(fs[-1],"rb").read()
print("  contexts=%s focused=%s fadeDur=%s parity=%s" % (
 " ".join("%02X"%b for b in raw[0:4]), " ".join("%02X"%b for b in raw[8:12]),
 " ".join("%02X"%b for b in raw[12:16]), " ".join("%02X"%b for b in raw[20:24])))
