import numpy as np, os
D=r"C:\ProgramData\scdump"
def look(name):
    p=os.path.join(D,name)
    raw=np.fromfile(p,dtype=np.uint8)
    f=raw.view(np.float32); q=raw.view(np.uint64)
    print(f"=== {name} ({len(raw)//1024} KB) ===")
    # pointer runs
    runs=0; i=0
    while i < len(q)-8:
        if all((int(q[i+k])>0x10000 and (int(q[i+k])&7)==0) for k in range(8)):
            runs+=1
            if runs<=2:
                print("  ptr-run at 0x%X: %s" % (i*8, " ".join("0x%X"%int(q[i+k]) for k in range(4))))
            i+=8
        else: i+=1
    print("  ptr-runs(>=8):", runs)
    # plausible float triples
    tri=0
    for i in range(0,len(f)-3):
        v=f[i:i+3]
        if not np.isfinite(v).all(): continue
        if np.abs(v).max()>20000 or np.abs(v).min()<1: continue
        if len(set(np.round(v,2)))<3: continue
        if tri<2: print("   triple@0x%X = (%.2f, %.2f, %.2f)" % (i*4, v[0],v[1],v[2]))
        tri+=1
    print("  triples:", tri)
for n in ("3_1D0000.bin","3_282E5000.bin","3_2A374000.bin","3_2748E000.bin"):
    look(n); print()
