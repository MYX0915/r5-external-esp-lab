import struct, glob, os, numpy as np
def load(a, size):
    hexv=a[2:]
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==size], key=os.path.getmtime)
    return open(fs[-1],"rb").read() if fs else None
me=open("me.txt").read().strip()
targets=[("me",me),("dummy",'0xEEB45660')]
for name,a in targets:
    raw=load(a,0x2000)
    if not raw: print("%s %s: no dump" % (name,a)); continue
    vt=struct.unpack_from("<Q", raw, 0)[0]
    p978=struct.unpack_from("<3f", raw, 0x978)
    pdd0=struct.unpack_from("<Q", raw, 0xDD0)[0]
    # ???????????????
    cands=[]
    for off in range(0x400, 0x1800, 8):
        v=struct.unpack_from("<Q", raw, off)[0]
        if 0x10000 < v < 0x7FFF00000000 and (v & 7)==0 and abs(v-int(a,16))>0x100000:
            cands.append((off,v))
    print("=== %s %s vt=0x%X ===" % (name,a,vt))
    print("   +0x978=(%.1f,%.1f,%.1f)  +0xDD0=0x%X" % (p978[0],p978[1],p978[2],pdd0))
    print("   ?????(?8):", [(hex(o),hex(v)) for o,v in cands[:8]])
