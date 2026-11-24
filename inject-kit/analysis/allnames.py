import glob, os, struct, collections
insts=[l.strip() for l in open("allinst.txt") if l.strip()]
names=[]
for a in insts:
    e=int(a,16); hexv="%X"%(e+0x590)
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x20], key=os.path.getmtime)
    if not fs: continue
    raw=open(fs[-1],"rb").read()
    n=0
    while n<len(raw) and 32<=raw[n]<127: n+=1
    if n>=4: names.append((raw[:n].decode('latin1'), a))
print("??????: %d / %d" % (len(names), len(insts)))
cnt=collections.Counter(n for n,_ in names)
print("\n=== ????? 20 ??? ===")
for n,c in cnt.most_common(20):
    print("  %-32s %d" % (n,c))
print("\n=== ? weapon / loot / ammo / gun / rifle ? ===")
kw=('weapon','loot','ammo','gun','rifle','wpn','pickup')
hit=[(n,a) for n,a in names if any(k in n.lower() for k in kw)]
for n,a in hit[:20]:
    print("  %-36s %s" % (n,a))
open("names_all.txt","w").write("\n".join("%s %s"%a_n if False else "%s %s"%(a,n) for n,a in names))
