import struct, glob, os, collections
insts=[l.strip() for l in open("allinst4.txt") if l.strip()]
hits=[]
for v in insts:
    e=int(v,16); hexv="%X"%(e+0x340)
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x4], key=os.path.getmtime)
    if not fs: continue
    t=struct.unpack_from("<I", open(fs[-1],"rb").read(),0)[0]
    if t==97: hits.append(v)
print("team==97: %d ?" % len(hits))
for h in hits: print("  %s" % h)
open("dummies4.txt","w").write("\n".join(hits))
