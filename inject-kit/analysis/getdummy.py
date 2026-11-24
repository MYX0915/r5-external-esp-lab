import struct, glob, os
insts=[l.strip() for l in open("allinst.txt") if l.strip()]
# ? signifier = npc_dummie ???
names={}
for p in [l.strip() for l in open("sigptrs.txt") if l.strip()]:
    e=int(p,16); hexv="%X"%e
    fs=sorted([x for x in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(x)==0x20], key=os.path.getmtime)
    if not fs: continue
    raw=open(fs[-1],"rb").read()
    n=0
    while n<len(raw) and 32<=raw[n]<127: n+=1
    names[e]=raw[:n].decode('latin1')
dummies=[]
for v in insts:
    e=int(v,16); hexv="%X"%(e+0x478)
    fs=sorted([x for x in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(x)==0x8], key=os.path.getmtime)
    if not fs: continue
    q=struct.unpack_from("<Q", open(fs[-1],"rb").read(),0)[0]
    if names.get(q)=="npc_dummie": dummies.append(v)
print("npc_dummie ??: %d ?" % len(dummies))
for d in dummies[:5]: print("  %s" % d)
open("dummies.txt","w").write("\n".join(dummies))
