import numpy as np, os
D=r"C:\ProgramData\scdump"
raw=np.fromfile(os.path.join(D,"1_mod1.bin"),dtype=np.uint8)
q=raw.view(np.uint64)
target_page = 0x1D0000
offs=[i for i in range(len(q)) if (int(q[i])>>12)==(target_page>>12)]
print("refs into page 0x%X: %d" % (target_page, len(offs)))
if offs:
    print("  first .data offsets:", [hex(o*8) for o in offs[:8]])
    print("  last  .data offsets:", [hex(o*8) for o in offs[-4:]])
    # stride analysis on the largest consecutive run
    runs=[]; start=offs[0]; prev=offs[0]
    for o in offs[1:]:
        if o==prev+1: prev=o; continue
        runs.append((start,prev)); start=o; prev=o
    runs.append((start,prev))
    runs.sort(key=lambda r:-(r[1]-r[0]))
    print("  top runs (as .data offsets):")
    for s,e in runs[:5]:
        print("    0x%08X .. 0x%08X  entries=%d stride=8" % (s*8, e*8, e-s+1))
