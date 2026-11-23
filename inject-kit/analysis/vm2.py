import numpy as np, glob, os
def show(fn, off, n=16):
    a=np.fromfile(fn, dtype=np.float32)
    i=off//4
    m=a[i:i+n]
    print("=== %s +0x%X ===" % (os.path.basename(fn), off))
    for r in range(n//4):
        print("   %10.6f %10.6f %10.6f %10.6f" % tuple(m[r*4:r*4+4]))
    rows=[m[0:3],m[4:7],m[8:11]]
    print("   ???:", ["%.4f"%float(np.linalg.norm(v)) for v in rows])
    print("   row0?row1=%.4f row0?row2=%.4f" % (float(np.dot(rows[0],rows[1])), float(np.dot(rows[0],rows[2]))))
    return m
show(r"C:\ProgramData\scdump\64_h3_60720000.bin", 0x9A1FC0)
print()
show(r"C:\ProgramData\scdump\64_h8_C2290000.bin", 0xF39118)
