import numpy as np
a=np.fromfile(r"C:\ProgramData\scdump\6_h9_C1A10000.bin",dtype=np.float32)
st=0x14CFFA0//4
print("first 4 matrices at +0x%X:" % (st*4))
for k in range(4):
    m=a[st+k*12: st+(k+1)*12]
    M=m.reshape(3,4)
    det=np.linalg.det(M[:, :3])
    print("  [%d] det=%.3f  t=(%8.2f,%8.2f,%8.2f)" % (k, det, m[3], m[7], m[11]))
    print("      row0=(%7.3f,%7.3f,%7.3f)  row1=(%7.3f,%7.3f,%7.3f)  row2=(%7.3f,%7.3f,%7.3f)" % tuple(m[0:3]) if False else "", end="")
    print("")
    print("      %7.3f %7.3f %7.3f | %7.3f %7.3f %7.3f | %7.3f %7.3f %7.3f" % (m[0],m[1],m[2],m[4],m[5],m[6],m[8],m[9],m[10]))
