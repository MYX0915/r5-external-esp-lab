import numpy as np, os
D=r"C:\ProgramData\scdump"
for nm in ("12E5C6D00.bin","12A6C3B90.bin","11EADF500.bin"):
    f1=os.path.join(D,"4_"+nm); f2=os.path.join(D,"5_"+nm)
    if not (os.path.exists(f1) and os.path.exists(f2)): continue
    a=np.fromfile(f1,dtype=np.float32); b=np.fromfile(f2,dtype=np.float32)
    n=min(len(a),len(b)); a=a[:n]; b=b[:n]
    print("=== %s ===" % nm)
    for base in (0x3B0, 0x690, 0x720):
        print("  @0x%03X" % base)
        for k in range(6):
            off=(base//4)+k
            print("     +0x%04X  %10.2f -> %10.2f" % (off*4, a[off], b[off]))
