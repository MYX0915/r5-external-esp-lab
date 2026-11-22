import mmap, os, re, struct
import numpy as np
DUMP=r'C:\ProgramData\scdump'; LOG=r'C:\ProgramData\kmaplog.txt'
ent={}
for line in open(LOG, errors='ignore'):
    m=re.search(r'^p([12]) va=0x([0-9A-Fa-f]+) size=0x([0-9A-Fa-f]+) idx=(\d+)', line)
    if m:
        p,va,sz,idx=int(m.group(1)),int(m.group(2),16),int(m.group(3),16),int(m.group(4))
        ent.setdefault((p,idx),(va,sz))
idx=35
base,_=ent[(1,idx)]
print('region base 0x%X' % base)
for target in (0x3B9FD610, 0x3B9FD618):
    off=target-base
    print('--- va 0x%X (off 0x%X) ---' % (target, off))
    for p in (1,2):
        f=os.path.join(DUMP, f'{p}{idx}_{base:08X}.bin')
        a=np.fromfile(f, dtype=np.float32)
        w=a[off//4: off//4+16]
        print(' p%d: %s' % (p, ' '.join('%.4f'%v for v in w)))
