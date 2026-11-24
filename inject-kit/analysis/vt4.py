import struct, glob, os, collections
ds=[l.strip() for l in open("dummies4.txt") if l.strip()]
def rd(e,off):
    hexv="%X"%(e+off)
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x8], key=os.path.getmtime)
    return struct.unpack_from("<Q", open(fs[-1],"rb").read(),0)[0] if fs else 0
print("????????:")
cnt=collections.Counter()
for d in ds:
    e=int(d,16)
    vt=rd(e,0); hp=rd(e,0x330)&0xFFFFFFFF; sh=rd(e,0x18C)&0xFFFFFFFF
    ok = "?" if (hp==100 and sh==125) else ""
    print("  %-12s vtable=0x%X  hp=%d sh=%d %s" % (d,vt,hp,sh,ok))
    if hp==100 and sh==125: cnt[vt]+=1
print("\n??????:")
for vt,c in cnt.most_common():
    print("  0x%X  (%d ?)" % (vt,c))
