import glob, os
for p in [l.strip() for l in open("players_now.txt")][:3]:
    e=int(p,16); hexv="%X"%(e+0x2A0)
    fs=sorted([x for x in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(x)==0x18], key=os.path.getmtime)
    if not fs: print("  %s ?dump" % p); continue
    raw=open(fs[-1],"rb").read()
    print("  %s contexts=%s focused=%s fade=%s parity=%s" % (p,
      " ".join("%02X"%b for b in raw[0:4]), " ".join("%02X"%b for b in raw[8:12]),
      " ".join("%02X"%b for b in raw[12:16]), " ".join("%02X"%b for b in raw[20:24])))
