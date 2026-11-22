import numpy as np, os
D=r"C:\ProgramData\scdump"
raw=np.fromfile(os.path.join(D,"1_mod1.bin"),dtype=np.uint8)
q=raw.view(np.uint64)
MOD=0x7FF779000000  # module base region (0x7FF779854000 .data, 0x7FF779EFC000)
def in_module(v): return 0x7FF779800000 <= v < 0x7FF77A000000
cands={}
for i in range(len(q)):
    v=int(q[i])
    if v < 0x10000 or v > 0x00007FFF00000000: continue
    if v & 7: continue
    if in_module(v): continue            # ???????
    cands[i]=v
print("heap-pointing qwords:", len(cands))
# ?????????? 12 ??????
from collections import Counter
c=Counter((v>>12) for v in cands.values())
print("top target pages:")
for page,cnt in c.most_common(12):
    print(f"   0x{page<<12:012X} x{cnt}")
