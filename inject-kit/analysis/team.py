import struct, glob, os
me=int(open("me_now.txt").read().strip(),16)
def rd(va,size):
    hexv="%X"%va
    fs=sorted([x for x in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(x)==size], key=os.path.getmtime)
    return open(fs[-1],"rb").read() if fs else None
r1=rd(me+0x330,0x8)
if r1: print("  +0x330 = %d / 0x%08X" % (struct.unpack_from("<i",r1,0)[0], struct.unpack_from("<I",r1,0)[0]))
r2=rd(me+0x334,0x8)
if r2: print("  +0x334 = %d / 0x%08X" % (struct.unpack_from("<i",r2,0)[0], struct.unpack_from("<I",r2,0)[0]))
