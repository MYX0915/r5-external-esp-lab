import numpy as np, glob, os
D=r"C:\ProgramData\scdump"
hits=0; tot=0
for f in sorted(glob.glob(os.path.join(D,"16_*.bin"))):
    va=int(os.path.basename(f).split("_")[1].split(".")[0],16)
    raw=np.fromfile(f,dtype=np.uint8); tot+=1
    if len(raw)<0x3778: continue
    p=np.frombuffer(raw[0x376C:0x376C+12],dtype=np.float32)
    if np.isfinite(p).all() and abs(p[0])<9000 and abs(p[1])<9000 and (abs(p[0])+abs(p[1])>1):
        hits+=1
        if hits<=12: print("  0x%-11X +0x376C=(%8.1f,%8.1f,%8.1f)" % (va,p[0],p[1],p[2]))
print("valid at +0x376C: %d / %d" % (hits,tot))
