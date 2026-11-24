import struct, glob, os
p0=open("players_now.txt").readline().strip(); e=int(p0,16)
def rd(va,size):
    hexv="%X"%va
    fs=sorted([x for x in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(x)==size], key=os.path.getmtime)
    return open(fs[-1],"rb").read() if fs else None
r1=rd(e+0x1D4,0x8)
if r1: print("  teamIndex = %d" % struct.unpack_from("<i",r1,0)[0])
r2=rd(e+0x2A8,0x10)
if r2:
    print("  focused = 0x%08X   parity = 0x%08X" % (
      struct.unpack_from("<I",r2,0)[0], struct.unpack_from("<I",r2,12)[0]))
