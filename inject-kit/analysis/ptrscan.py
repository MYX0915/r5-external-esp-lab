import struct, glob, os
t=int(open("ptarget.txt").read().strip(),16)
hexv="%X"%t
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x1000], key=os.path.getmtime)
if not fs: print("?dump"); raise SystemExit
raw=open(fs[-1],"rb").read()
ptrs=[]
for i in range(0,0x1000,8):
    q=struct.unpack_from("<Q",raw,i)[0]
    if q==0: continue
    if 0x10000 < q < 0x7FFF00000000 and (q&7)==0:
        ptrs.append((i,q))
print("?? 0x%X  ???? %d ?" % (t,len(ptrs)))
for off,q in ptrs[:30]:
    print("  +0x%03X -> 0x%X" % (off,q))
open("childptr.txt","w").write("\n".join("%d %d"%(o,q) for o,q in ptrs[:40]))
