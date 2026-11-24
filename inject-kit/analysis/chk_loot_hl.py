import glob, os
loots=[l.split()[0] for l in open(r"C:\ProgramData\sc_loot.txt") if l.startswith("0x")][:4]
for l in loots:
    e=int(l,16); hexv="%X"%(e+0x2A0)
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x18], key=os.path.getmtime)
    if not fs: print("  %s ?dump" % l); continue
    raw=open(fs[-1],"rb").read()
    print("  %s contexts=%s focused=%s fade=%s parity=%s" % (l,
      " ".join("%02X"%b for b in raw[0:4]), " ".join("%02X"%b for b in raw[8:12]),
      " ".join("%02X"%b for b in raw[12:16]), " ".join("%02X"%b for b in raw[20:24])))
