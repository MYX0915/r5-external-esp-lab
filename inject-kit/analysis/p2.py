import numpy as np, struct, glob, os
f=[p for p in glob.glob(r"C:\ProgramData\scdump\7_*.bin") if os.path.getsize(p)>0x1000]
raw=open(f[0],"rb").read()
feed=open(r"C:\ProgramData\sc_feed.bin","rb").read()
pos=struct.unpack_from("<3f",feed,32)
print("player pos from feed:", ["%.1f"%v for v in pos])
# find where the position appears inside the object
fl=np.frombuffer(raw,dtype=np.float32)
for i in range(len(fl)-3):
    if abs(fl[i]-pos[0])<0.5 and abs(fl[i+1]-pos[1])<0.5 and abs(fl[i+2]-pos[2])<0.5:
        print("  pos found at +0x%X" % (i*4))
