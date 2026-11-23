import struct, glob, os
addrs=[l.strip() for l in open("players.txt") if l.strip()]
ok=[]; bad=0; vals=[]
for a in addrs:
    hexv=a[2:]
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x400], key=os.path.getmtime)
    if not fs: continue
    raw=open(fs[-1],"rb").read()
    p=struct.unpack_from("<Q", raw, 0x298)[0]
    vals.append((a,p))
    if 0x10000 < p < 0x7FFF00000000 and (p & 3)==0: ok.append((a,p))
    else: bad+=1
print("???? %d ??+0x298 ???? %d ???? %d ?" % (len(vals),len(ok),bad))
print("\n? 12 ???? +0x298 ??:")
for a,p in vals[:12]:
    print("   %s  0x%016X" % (a,p))
