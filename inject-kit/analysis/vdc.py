import struct, glob, os
fs=sorted(glob.glob(r"C:\ProgramData\scdump\vd*.bin"), key=os.path.getmtime, reverse=True)[:40]
print("vd dumps:", len(fs))
cnt=0
for f in fs:
    raw=open(f,"rb").read()
    if len(raw) < 0x3780: continue
    p=struct.unpack_from("<3f", raw, 0x376C)
    if abs(p[0])>100 or abs(p[1])>100:
        cnt+=1
        if cnt<=6: print("   %-18s +0x376C=(%9.1f,%9.1f,%9.1f)" % (os.path.basename(f), p[0],p[1],p[2]))
print("objects with a plausible position:", cnt)
