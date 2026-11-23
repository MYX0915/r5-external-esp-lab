import struct, glob, os, collections
insts=[l.strip() for l in open("allinst.txt")]
groups=collections.defaultdict(list)
for a in insts:
    hexv=a[2:]
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x1000], key=os.path.getmtime)
    if not fs: continue
    vt=struct.unpack_from("<Q", open(fs[-1],"rb").read(), 0)[0]
    groups[vt].append(a)
print("??: %d" % len(groups))
print("\n??? 1~12 ????????/???:")
for vt,l in sorted(groups.items(), key=lambda kv: len(kv[1])):
    if 1 <= len(l) <= 12:
        print("   0x%-14X n=%-3d  %s" % (vt, len(l), " ".join(x[2:] for x in l[:6])))
