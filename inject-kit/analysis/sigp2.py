import struct, glob, os
insts=[l.strip() for l in open("allinst2.txt") if l.strip()]
ptrs=[]
for v in insts:
    e=int(v,16); hexv="%X"%(e+0x478)
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x8], key=os.path.getmtime)
    if not fs: continue
    q=struct.unpack_from("<Q", open(fs[-1],"rb").read(),0)[0]
    if 0x10000 < q < 0x7FFF00000000 and (q&7)==0: ptrs.append(q)
uniq=sorted(set(ptrs))
print("?????? %d" % len(uniq))
open("sigptrs2.txt","w").write("\n".join("0x%X"%q for q in uniq))
