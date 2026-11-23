import struct, glob, os
addrs=[l.split()[0] for l in open(r"C:\ProgramData\sc_ents.txt") if l.strip()]
ok=[]; bad=0
for a in addrs:
    hexv=a[2:]
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x400], key=os.path.getmtime)
    if not fs: continue
    raw=open(fs[-1],"rb").read()
    p=struct.unpack_from("<Q", raw, 0x298)[0]
    if 0x10000 < p < 0x7FFF00000000 and (p & 3)==0:
        ok.append((a,p))
    else:
        bad+=1
print("+0x298 ????????: %d / %d  (?? %d ???)" % (len(ok),len(addrs),bad))
for a,p in ok[:10]:
    print("   %s  +0x298 = 0x%X" % (a,p))
if ok:
    open("ctxcand.txt","w").write("\n".join("0x%X 0x20"%p for _,p in ok[:10]))
