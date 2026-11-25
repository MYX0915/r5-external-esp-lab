import struct, glob, os
e=int(open("other.txt").read().strip(),16)
print("?? 0x%X ? cell+origin ??:" % e)
for blk in (0x0,0x1000,0x2000,0x3000,0x4000,0x5000):
    va=e+blk; hexv="%X"%va
    fs=sorted([x for x in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(x)==0x1000], key=os.path.getmtime)
    if not fs: continue
    raw=open(fs[-1],"rb").read()
    for off in range(0,0x1000-24,4):
        a,b,c=struct.unpack_from("<3i",raw,off)
        # cell ??????????????? 0x18 ????????
        if not (abs(a)<300 and abs(b)<300 and abs(c)<300): continue
        if a==0 and b==0 and c==0: continue
        f3=struct.unpack_from("<3f",raw,off+0x18)
        if not (100<abs(f3[0])<20000 and abs(f3[1])<20000 and -800<f3[2]<3000): continue
        print("  +0x%05X cell=(%d,%d,%d)  +0x18 origin=(%.1f,%.1f,%.1f)" % (blk+off,a,b,c,f3[0],f3[1],f3[2]))
