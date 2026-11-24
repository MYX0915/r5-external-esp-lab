import struct, glob, os, collections
# ?????? signifier ??
insts=[l.strip() for l in open("allinst.txt") if l.strip()]
# ??????????
namemap={}
for p in [l.strip() for l in open("sigptrs.txt") if l.strip()]:
    e=int(p,16); hexv="%X"%e
    fs=sorted([x for x in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(x)==0x20], key=os.path.getmtime)
    if not fs: continue
    raw=open(fs[-1],"rb").read()
    n=0
    while n<len(raw) and 32<=raw[n]<127: n+=1
    namemap[e]=raw[:n].decode('latin1')
rows=[]
for v in insts:
    e=int(v,16); hexv="%X"%(e+0x478)
    fs=sorted([x for x in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(x)==0x8], key=os.path.getmtime)
    if not fs: continue
    q=struct.unpack_from("<Q", open(fs[-1],"rb").read(),0)[0]
    nm=namemap.get(q,"")
    rows.append((nm,v))
cnt=collections.Counter(nm for nm,_ in rows)
print("?????:")
for nm,c in cnt.most_common(12):
    print("  %-30s %d" % (nm if nm else "(?)", c))
for want in ("weaponx","prop_loot_grabber","prop_script"):
    sel=[v for nm,v in rows if nm==want]
    print("\n%s: %d ?" % (want, len(sel)))
    for v in sel[:6]: print("   %s" % v)
    open("sig_%s.txt"%want,"w").write("\n".join(sel))
