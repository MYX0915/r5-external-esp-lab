import numpy as np, glob, os
def scan(a, stride, trans_off, n=32):
    out=[]
    limit = len(a) - (n*stride)//4
    for start in range(0, max(0,limit), 4):
        ok=0; vals=[]
        for k in range(n):
            base = (start + k*stride)//4
            if base+3 > len(a): break
            v = a[base+trans_off//4: base+trans_off//4+3]
            if not np.isfinite(v).all(): break
            if max(abs(v[0]),abs(v[1]),abs(v[2]))>9000: break
            if abs(v[0])+abs(v[1]) < 1: break
            ok+=1
            vals.append(v.copy())
        if ok >= n-1:
            spread = max(abs(vals[0][0]-vals[-1][0]), abs(vals[0][1]-vals[-1][1]))
            out.append((start, spread))
    return out
for f in sorted(glob.glob(r"C:\ProgramData\scdump\9_*.bin"))[:2]:
    if os.path.getsize(f)<0x1000: continue
    a=np.fromfile(f,dtype=np.float32)
    print("=== %s (%d floats) ===" % (os.path.basename(f), len(a)))
    for stride, toff in ((0x40,0x30),(0x30,0x24),(0x40,0x00)):
        hits=scan(a,stride,toff)
        print("  stride=0x%X trans@+0x%X -> %d hits %s" % (stride,toff,len(hits), [hex(h[0]) for h in hits[:4]]))
