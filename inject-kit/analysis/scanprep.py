import struct, math, subprocess, time, os

FEED = r"C:\ProgramData\sc_feed.bin"

def feed():
    f = open(FEED, "rb").read()
    cam = struct.unpack_from("<3f", f, 8)
    cnt = struct.unpack_from("<I", f, 44)[0]
    ents = [struct.unpack_from("<3f", f, 64 + i*12) for i in range(cnt)]
    return cam, ents

cam, ents = feed()
print("cam=(%.0f,%.0f,%.0f)  ???? %d ?" % (cam[0],cam[1],cam[2],len(ents)))
near = [(math.dist(e,cam), i, e) for i,e in enumerate(ents)]
near = [x for x in near if 100 < x[0] < 3000]
near.sort()
print("?? 100~3000 ???:", len(near))
for d,i,e in near[:12]:
    print("   ent[%2d] %6.0f ?? (%.0f,%.0f,%.0f)" % (i,d,e[0],e[1],e[2]))
