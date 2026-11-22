import numpy as np, glob, os, struct
fs=[f for f in glob.glob(r"C:\ProgramData\scdump\5_*.bin") if os.path.getsize(f)==0x8000]
print("dumped:", len(fs))
for f in fs:
    raw=open(f,"rb").read()
    vt=struct.unpack_from("<Q", raw, 0)[0]
    p=struct.unpack_from("<3f", raw, 0x376C)
    if vt == 0x7FF779A400E8 or (abs(p[0])>100 and abs(p[0])<100000):
        print("   %-18s vt=0x%-14X pos=(%9.1f,%9.1f,%9.1f)" % (os.path.basename(f), vt, p[0],p[1],p[2]))
