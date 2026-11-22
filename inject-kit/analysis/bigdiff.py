import numpy as np, glob, os, collections
insts=[l.strip() for l in open("all869.txt") if l.strip()]
print("diffing %d entities (two rounds)..." % len(insts))
hits=[]
for v in insts:
    hexv=v[2:]
    fs=sorted([p for p in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(p)==0x4000], key=os.path.getmtime)
    if len(fs)<2: continue
    a=np.fromfile(fs[-2],dtype=np.float32); b=np.fromfile(fs[-1],dtype=np.float32)
    n=min(len(a),len(b))
    with np.errstate(invalid="ignore"):
        d=np.abs(a[:n]-b[:n])
        m=np.isfinite(d)&(d>0.2)&(d<2000)
    idx=np.nonzero(m)[0]
    if not len(idx): continue
    # keep only slots where values look like world coordinates
    ws=[i for i in idx if 500<abs(a[i])<40000 and 500<abs(b[i])<40000]
    if ws:
        hits.append((len(ws), v, fs[-2], fs[-1], [(int(i*4),float(a[i]),float(b[i])) for i in ws[:4]]))
hits.sort(reverse=True)
print("entities with world-scale changes: %d" % len(hits))
for c,v,fa,fb,det in hits[:10]:
    print("  %s  n=%d  %s -> %s" % (v,c,os.path.basename(fa),os.path.basename(fb)))
    for off,x,y in det:
        print("      +0x%05X  %.2f -> %.2f" % (off,x,y))
