import numpy as np, os, glob, re
D=r"C:\ProgramData\scdump"
LOG=r"C:\ProgramData\kmaplog.txt"
# map heap index -> va  (from snapshot 1)
va={}
for line in open(LOG, errors='ignore'):
    m=re.search(r'snap 1 heap (\d+) va=0x([0-9A-Fa-f]+) size=0x([0-9A-Fa-f]+)', line)
    if m: va[int(m.group(1))]=(int(m.group(2),16), int(m.group(3),16))
print("regions:", len(va))
hits=[]
for idx,(base,size) in sorted(va.items()):
    f1=os.path.join(D,f"1_h{idx}_{base:X}.bin"); f2=os.path.join(D,f"2_h{idx}_{base:X}.bin")
    if not (os.path.exists(f1) and os.path.exists(f2)): continue
    a=np.fromfile(f1,dtype=np.float32); b=np.fromfile(f2,dtype=np.float32)
    n=min(len(a),len(b)); a=a[:n]; b=b[:n]
    w1=np.lib.stride_tricks.sliding_window_view(a,3)
    w2=np.lib.stride_tricks.sliding_window_view(b,3)
    fin=np.isfinite(w1).all(axis=1)&np.isfinite(w2).all(axis=1)
    rng=(np.abs(w1)<8000).all(axis=1)&(np.abs(w2)<8000).all(axis=1)
    nonz=(np.abs(w1)>1).all(axis=1)
    ch=(w1!=w2).sum(axis=1)
    mask=fin&rng&nonz&(ch==3)
    for off in np.nonzero(mask)[0][:200]:
        hits.append((base+off*4, tuple(np.round(w1[off],2)), tuple(np.round(w2[off],2))))
print("triple candidates (all 3 changed):", len(hits))
for h in hits[:15]:
    print("  0x%012X  %s -> %s" % (h[0], h[1], h[2]))
