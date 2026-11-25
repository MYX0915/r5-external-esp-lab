import struct, glob, os, numpy as np
hits=[l.strip() for l in open(r"C:\ProgramData\sc_hits.txt") if l.startswith("0x")]
print("?? %d ???" % len(hits))
insts=[int(l.strip(),16) for l in open("..\..\..\test-game\inject-kit\analysis\allinst4.txt")] if os.path.exists("allinst4.txt") else []
# ??????
import glob as g
es=[x for x in g.glob(r"C:\ProgramData\sc_ents.txt")]
cur=[int(l.split()[0],16) for l in open(es[0]) if l.startswith("0x")] if es else []
print("???? %d ?" % len(cur))
print("\n???????:")
for h in hits[:40]:
    a=int(h,16)
    owner=None
    for i in cur:
        if i <= a < i+0x10000:
            owner=(i, a-i); break
    print("  %s  %s" % (h, ("?? 0x%X ?? +0x%X" % owner) if owner else "?????????"))
