import struct, glob, os, collections
addrs=[l.strip() for l in open(r"C:\ProgramData\sc_addr.txt") if l.strip()]
rows=[]
for a in addrs:
    hexv=a[2:]
    fs=[p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x1000]
    if not fs: continue
    fs.sort(key=os.path.getmtime)
    raw=open(fs[-1],"rb").read()
    vt=struct.unpack_from("<Q", raw, 0)[0]
    v298=struct.unpack_from("<Q", raw, 0x298)[0]
    rows.append((a,vt,v298))
print("???: %d\n" % len(rows))
print("%-14s %-20s %-20s %s" % ("entity","vtable","+0x298","low32"))
for a,vt,v in rows[:24]:
    print("%-14s 0x%-18X 0x%-18X 0x%08X" % (a[2:],vt,v,v & 0xFFFFFFFF))
# ??????
hi=collections.Counter((v>>32)&0xFFFF for _,_,v in rows if v)
print("\n+0x298 ?16???(?8):")
for k,c in hi.most_common(8):
    print("   0x%04X : %d" % (k,c))
lo=[v & 0xFFFF for _,_,v in rows if v]
print("\n+0x298 ?16???: 0x%X ~ 0x%X" % (min(lo),max(lo)) if lo else "n/a")
