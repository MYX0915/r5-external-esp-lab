import struct, glob, os, numpy as np
e=0x132D22B80
f=open(r"C:\ProgramData\sc_feed.bin","rb").read()
pos=np.array(struct.unpack_from("<3f",f,32), dtype=np.float64)
print("??: (%.1f,%.1f,%.1f)" % (pos[0],pos[1],pos[2]))
raw=None
for cand in (0x8000,):
    hexv="%X"%(e+cand)
    fs=sorted([x for x in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(x)==0x1000], key=os.path.getmtime)
if True:
    hexv="%X"%(e+0x7000)
    fs=sorted([x for x in glob.glob(r"C:\ProgramData\scdump\*_%s.bin"%hexv) if os.path.getsize(x)==0x1000], key=os.path.getmtime)
    if fs:
        raw=open(fs[-1],"rb").read()
        for off in (0x7830,0x7834):
            fo=off-0x7000
            if fo+12<=len(raw):
                t=struct.unpack_from("<3f",raw,fo)
                d=float(np.linalg.norm(np.array(t)-pos))*0.01905
                print("  +0x%X = (%.2f, %.2f, %.2f)  ??? %.1f ?" % (off,t[0],t[1],t[2],d))
