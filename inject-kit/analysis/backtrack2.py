import struct, glob, os
anchor=0x4924DC8
base=anchor-0x2000
hexv="%X"%base
fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x2000], key=os.path.getmtime)
if not fs: print("?dump"); raise SystemExit
raw=open(fs[-1],"rb").read()
print("dump 0x%X ~ 0x%X\n" % (base, base+0x2000))
cands=[]
for i in range(0, len(raw)-8, 8):
    q=struct.unpack_from("<Q",raw,i)[0]
    if 0x7FF000000000 <= q <= 0x7FFFFFFFFFFF:
        cands.append((base+i, q))
print("???????: %d ?" % len(cands))
for va,q in cands[:15]:
    print("  0x%X = 0x%X   ??? %+d" % (va,q,va-anchor))
