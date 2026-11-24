import struct, glob, os
me=int(open("me_now.txt").read().strip(),16)
def rd(va,size):
    hexv="%X"%va
    fs=sorted([x for x in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(x)==size], key=os.path.getmtime)
    return open(fs[-1],"rb").read() if fs else None
r1=rd(me+0x1F7C,0x10)
if r1:
    print("camera +0x1F78 = (%.2f,%.2f,%.2f)" % struct.unpack_from("<3f",r1,0))
    print("angles +0x1F84 = (%.2f,%.2f,%.2f)" % struct.unpack_from("<3f",r1,4))
r2=rd(me+0x25C0,0x10)
if r2:
    print("+0x25C0 = %s" % " ".join("%02X"%b for b in r2))
    print("m_viewangle +0x25C8 = (%.2f,%.2f,%.2f)" % struct.unpack_from("<3f",r2,8))
