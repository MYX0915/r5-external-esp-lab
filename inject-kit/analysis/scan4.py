import numpy as np, os, glob
D=r"C:\ProgramData\scdump"
files=sorted(glob.glob(os.path.join(D,"4_*.bin")))
print("scanning", len(files), "pages")
for p in files:
    raw=np.fromfile(p,dtype=np.uint8)
    q=raw.view(np.uint64); f=raw.view(np.float32)
    # pointer runs into heap
    runs=0; i=0
    while i < len(q)-8:
        if all(0x10000 < int(q[i+k]) < 0x7FFF00000000 and (int(q[i+k])&7)==0 for k in range(8)):
            runs+=1; i+=8
        else: i+=1
    # world-range triples
    tri=0
    for i in range(0,len(f)-3):
        v=f[i:i+3]
        if not np.isfinite(v).all(): continue
        if np.abs(v).max()>8000 or np.abs(v).min()<1: continue
        if len(set(np.round(v,1)))<3: continue
        tri+=1
    if runs or tri>50:
        print(f"{os.path.basename(p):24s} ptr-runs={runs:4d} triples={tri:5d}")
