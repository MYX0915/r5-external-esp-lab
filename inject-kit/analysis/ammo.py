import numpy as np, os, glob, re
D=r"C:\ProgramData\scdump"
LOG=r"C:\ProgramData\kmaplog.txt"
va={}
for line in open(LOG, errors="ignore"):
    m=re.search(r'snap 3 heap (\d+) va=0x([0-9A-Fa-f]+) size=0x([0-9A-Fa-f]+)', line)
    if m: va[int(m.group(1))]=int(m.group(2),16)
print("regions:", len(va))
hits=[]
for idx,base in sorted(va.items()):
    f1=os.path.join(D,f"3_h{idx}_{base:X}.bin"); f2=os.path.join(D,f"4_h{idx}_{base:X}.bin")
    if not (os.path.exists(f1) and os.path.exists(f2)): continue
    a=np.fromfile(f1,dtype=np.int32); b=np.fromfile(f2,dtype=np.int32)
    n=min(len(a),len(b)); a=a[:n]; b=b[:n]
    idxs=np.nonzero((a==19)&(b==18))[0]
    for i in idxs:
        hits.append((base+i*4, "int"))
    fa=np.fromfile(f1,dtype=np.float32); fb=np.fromfile(f2,dtype=np.float32)
    idxs=np.nonzero((np.abs(fa[:n]-19.0)<1e-4)&(np.abs(fb[:n]-18.0)<1e-4))[0]
    for i in idxs:
        hits.append((base+i*4, "flt"))
print("19->18 candidates:", len(hits))
for va_,t in hits[:25]:
    print("  0x%012X  %s" % (va_, t))
