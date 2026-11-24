import struct, glob, os
for d in [l.strip() for l in open("dummies.txt") if l.strip()][:3]:
    e=int(d,16); hexv="%X"%(e+0x18C)
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x520], key=os.path.getmtime)
    if not fs: print("%s ?dump" % d); continue
    b=open(fs[-1],"rb").read()
    sh=struct.unpack_from("<I",b,0x000)[0]
    shM=struct.unpack_from("<I",b,0x004)[0]
    hp=struct.unpack_from("<I",b,0x1A4)[0]
    hpM=struct.unpack_from("<I",b,0x2E4)[0]
    team=b[0x1B4]; life=b[0x50C]
    nm=b[0x2F5:0x2F5+20].split(b'\x00')[0].decode('latin1','replace')
    print("  %s hp=%d/%d sh=%d/%d team=%d life=%d name='%s'" % (d,hp,hpM,sh,shM,team,life,nm))
