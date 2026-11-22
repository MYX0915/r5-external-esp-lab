import struct, glob, os
f=sorted(glob.glob(r"C:\ProgramData\scdump\vd*.bin"), key=os.path.getmtime, reverse=True)[0]
raw=open(f,"rb").read()
seen=set(); out=[]
for off in range(0, 0x4000-8, 8):
    v=struct.unpack_from("<Q", raw, off)[0]
    if not (0x100000 < v < 0x00007FFF00000000): continue
    if v & 0xF: continue                      # require 16-byte alignment
    if 0x7FF687000000 <= v <= 0x7FF688000000: continue   # module .text/.rdata
    if v in seen: continue
    seen.add(v); out.append((off, v))
print("aligned heap pointers:", len(out))
for off,v in out[:12]: print("   +0x%04X -> 0x%X" % (off,v))
open("bonechase2.txt","w").write("\n".join("0x%X 0x4000"%v for _,v in out[:12]))
