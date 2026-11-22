import struct, glob, os
fs=[f for f in glob.glob(r"C:\ProgramData\scdump\1?_*.bin") if os.path.getsize(f)==0x4000]
print("dumped:", len(fs))
n=0
for f in fs:
    raw=open(f,"rb").read()
    p=struct.unpack_from("<3f", raw, 0x376C)
    if abs(p[0])>100 or abs(p[1])>100:
        n+=1
        if n<=8: print("   %-18s +0x376C=(%10.1f,%10.1f,%10.1f)" % (os.path.basename(f), p[0],p[1],p[2]))
print("with position:", n)
